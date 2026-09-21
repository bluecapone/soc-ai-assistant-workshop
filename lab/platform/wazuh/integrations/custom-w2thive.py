#!/usr/bin/env python3
"""
Wazuh -> TheHive integrator.

Turns Wazuh alerts into TheHive cases over the REST API, merging the alerts that share an
attacker IP into one case so a single attack is one incident, not several. This is the
Wazuh-to-TheHive seam ADR-0006 flags as load-bearing: prove it end to end before building an
image around it. Uses only the standard library, since Wazuh's bundled interpreter may not
carry `requests`.

Called by the `custom-w2thive` wrapper with:
  argv[1] = alert JSON file, argv[2] = api_key, argv[3] = hook_url (TheHive base URL)

Attack alerts are keyed on the external attacker IP (srcip inbound, dstip for c2/exfil). A
per-IP lock and a small IP-to-case state file on the manager make the get-or-create atomic, so
the second detection of one press appends to the first's case instead of opening a new one.
"""

import contextlib
import fcntl
import json
import os
import sys
import time as _time
import urllib.parse
import urllib.request
import urllib.error

# We trigger the n8n triage workflow from this integrator, not from TheHive's own
# webhook notifier: that notifier is an Enterprise-licensed capability and does not
# fire under the trial/community license this lab runs on (the config is accepted but
# silently never delivered). Triggering here — right after we create the case — is
# license-independent and fires exactly once per case. Override with N8N_WEBHOOK_URL.
N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL", "http://n8n:5678/webhook/thehive-alert")
N8N_TRIGGER_DELAY = int(os.environ.get("N8N_TRIGGER_DELAY", "3"))  # seconds; lets siblings append first
# Browser-facing dashboard URL, so the case can link straight to the alert that made it.
WAZUH_DASHBOARD_URL = os.environ.get("WAZUH_DASHBOARD_URL", "http://wazuh.localhost")


def alert_link(alert_id: str) -> str:
    """Discover deep link that shows exactly this alert (`id` is the manager's alert id)."""
    q = urllib.parse.quote(f'id:"{alert_id}"', safe="")
    return (f"{WAZUH_DASHBOARD_URL}/app/data-explorer/discover#?"
            f"_a=(metadata:(indexPattern:'wazuh-alerts-*',view:discover))"
            f"&_g=(time:(from:now-7d,to:now))"
            f"&_q=(query:(language:kuery,query:'{q}'))")


def severity_from_level(level: int) -> int:
    """Map a Wazuh rule level (0-15) to a TheHive severity (1-4)."""
    if level >= 12:
        return 3  # high
    if level >= 8:
        return 2  # medium
    return 1      # low


# Rule -> (MITRE technique id, name) for the attack rules.
MITRE = {
    "100100": ("T1595", "Active Scanning"),
    "100110": ("T1190", "Exploit Public-Facing Application"),
    "100120": ("T1110", "Brute Force"),
    "100130": ("T1059", "Command and Scripting Interpreter"),
    "100131": ("T1505.003", "Server Software Component: Web Shell"),
    "100140": ("T1071", "Application Layer Protocol"),
    "100142": ("T1567", "Exfiltration Over Web Service"),
    "100150": ("T1083", "File and Directory Discovery"),
    "100160": ("T1110", "Brute Force"),
    "100161": ("T1021.004", "Remote Services: SSH"),
    "100162": ("T1110", "Brute Force"),
    "100163": ("T1110", "Brute Force"),
    "100170": ("T1566", "Phishing"),
}
# Rule -> one-line "what to check" hint for the analyst / AI.
HINTS = {
    "100100": "Confirm the source is not a sanctioned scanner before dismissing; a 404 burst precedes exploitation.",
    "100110": "Check whether the injection succeeded (data returned / auth bypassed) and what data is exposed.",
    "100120": "Look for a successful login from the same source after the failures — that is the pivot point.",
    "100130": "Treat as hands-on-keyboard: identify the command in the query string and any follow-on activity from the host.",
    "100131": "A file uploaded to the web root is likely a web shell; retrieve it and check for a paired request that runs it.",
    "100140": "Resolve and reputation-check the callout domain; correlate with any prior compromise on the host.",
    "100142": "Confirm the destination is external and unsanctioned — a large transfer to an unknown host via a grab tool is exfiltration; internal backups never leave the network.",
    "100143": "Confirm the destination is the internal backup server and the agent is a sanctioned backup tool (Veeam) before dismissing.",
    "100150": "Path traversal is high-confidence — identify which file was requested (/etc/passwd, source, config) and whether its contents were returned.",
    "100160": "Look for a successful SSH login from the same IP right after — that is the compromise moment.",
    "100161": "A successful SSH login: decide by the source IP reputation and whether brute force preceded it from the same address.",
    "100162": "The brute force succeeded; identify the compromised account, reset it, and hunt this source's activity after the successful login.",
    "100163": "The SSH brute force succeeded; identify the compromised account, reset it, and hunt this source's activity after the successful login.",
    "100170": "Check the sender IP and the embedded URL reputation; confirm whether the recipient clicked, and the attachment hash.",
}

# Rule -> a plain-English narrative for the analyst: what happened, how the rule triggered,
# and why it matters. Filled with the alert's own fields.
SUMMARY = {
    "100100": "A single source (`{srcip}`) requested many missing paths on `{host}` in a short "
              "window, returning a burst of HTTP 404s, with a scanner-style user-agent. Rule {id} "
              "fires on repeated 404s from one source. Review the paths probed and whether this "
              "source and scanning activity are expected.",
    "100110": "A request from `{srcip}` to `{url}` carried SQL-injection syntax (a tautology, "
              "UNION SELECT, or comment sequences). Rule {id} matches SQLi patterns in the request "
              "URL. Check the endpoint's response and whether the query returned or changed data.",
    "100120": "Many failed logins (`authresult=failure`) from `{srcip}`, across multiple usernames, "
              "against the login form within the window tripped rule {id}. Check whether any login "
              "from this source then succeeded, and the source's reputation.",
    "100121": "A successful login from `{srcip}` (rule {id}). Check the source's reputation and "
              "whether failed attempts from the same address preceded it.",
    "100130": "A request from `{srcip}` invoked an uploaded script at `{url}` on `{host}`. Rule {id} "
              "fires on a request to a `.php` file under the served upload directory, the attacker "
              "running a web shell they planted. Identify the command in the query string and whether "
              "it returned output.",
    "100131": "A `POST` from `{srcip}` uploaded a file to `{url}` on `{host}`. Rule {id} fires on an "
              "upload to the web upload endpoint. Retrieve the file and check for a paired request that "
              "invokes it from the same source.",
    "100140": "`{host}` made repeated outbound proxy connections to `{dst_host}` (`{dstip}`) at a "
              "regular interval (source `{srcip}`). Rule {id} fires on this beacon frequency from "
              "the internal host. Look up the destination's reputation and correlate with any prior "
              "compromise on the host.",
    "100141": "`{host}` made an outbound proxy connection to `{dst_host}` (`{dstip}`), a marketing/CDN destination (source `{srcip}`). Rule {id} fires on a destination the proxy categorised as CDN. Confirm the destination is a sanctioned CDN on your allow-list.",
    "100142": "A large data transfer ({size}) left `{host}` for the EXTERNAL destination "
              "`{dst_host}` (`{dstip}`) using `{user_agent}`. Rule {id} fires on high-volume "
              "egress. Check the destination's reputation and whether this transfer and tool are "
              "authorised — internal backups never go to an external host.",
    "100143": "A large data transfer ({size}) from `{host}` to `{dst_host}` (`{dstip}`) using "
              "`{user_agent}`. Rule {id} fires on high-volume egress. Confirm the destination is "
              "the internal backup server and the agent is a sanctioned backup tool before "
              "dismissing.",
    "100150": "A request from `{srcip}` to `{url}` contains a directory-traversal pattern (`../` "
              "walks, encoded traversal, or a path to a system file like /etc/passwd). Rule {id} "
              "matches traversal syntax in the URL. Check which file was requested and whether the "
              "response returned its contents.",
    "100151": "High request volume from `{srcip}` using a search-engine crawler user-agent "
              "(Googlebot/bingbot). Rule {id} fires on a high request count from one source. Verify "
              "whether the user-agent and source match a real crawler.",
    "100160": "Repeated failed SSH logins from `{srcip}`, across multiple accounts, against "
              "`{host}` tripped Wazuh's SSH brute-force detection (rule {id}). Check whether a login "
              "from this source then succeeded, and the source's reputation.",
    "100161": "A successful SSH login for `{dstuser}` from `{srcip}` on `{host}` (rule {id}). Check "
              "whether failed attempts from the same address preceded it, and the source's "
              "reputation.",
    "100162": "A successful web login from `{srcip}` immediately followed repeated failed attempts "
              "from the same source on `{host}`. Rule {id} fires on a login success preceded by "
              "brute-force failures from the same source - the breakthrough. Treat as a credential "
              "compromise: identify the account that fell and hunt this source's activity after login.",
    "100163": "A successful SSH login from `{srcip}` immediately followed repeated failed SSH attempts "
              "from the same source on `{host}`. Rule {id} fires on an SSH login success preceded by "
              "brute-force failures from the same source - the breakthrough. Treat as a credential "
              "compromise: identify the account that fell and hunt this source's activity after login.",
    "100170": "The mail gateway flagged an email to `{dstuser}` from `{mail_from}` (sender IP "
              "`{srcip}`) as suspicious. It carries the link `{url}` and the attachment "
              "`{attachment}`. Rule {id} fires on the gateway's suspicious verdict; the gateway did "
              "not classify it, so confirm via the attachment hash and the link reputation.",
    "100171": "The mail gateway delivered an email to `{dstuser}` from `{mail_from}` and assigned "
              "it verdict=clean, with the attachment `{attachment}` and a link on the sender's "
              "domain. Confirm the sender and link before dismissing.",
}


def summarize(rule_id: str, data: dict, level: int, host: str) -> str:
    """A short narrative of what happened and how the rule fired, filled with alert fields.
    Describes the observation and suggested checks only — it does not declare a verdict
    (benign vs attack); that is the analyst's / AI's job to decide."""
    try:
        _b = int(data.get("bytes", 0))
        _size = f"{_b/1e9:.1f} GB" if _b >= 1_000_000_000 else f"{_b/1e6:.0f} MB"
    except (TypeError, ValueError):
        _size = str(data.get("bytes", "n/a"))
    ctx = {
        "srcip": data.get("srcip", "n/a"),
        "url": data.get("url", "n/a"),
        "dstuser": data.get("dstuser") or data.get("user") or data.get("mail_to") or "n/a",
        "mail_from": data.get("mail_from", "n/a"),
        "attachment": data.get("attachment", "n/a"),
        "dst_host": data.get("dst_host", "n/a"),
        "dstip": data.get("dstip", "n/a"),
        "size": _size,
        "user_agent": data.get("user_agent", "n/a"),
        "host": host,
        "id": rule_id,
        "level": level,
    }
    tmpl = SUMMARY.get(rule_id)
    if tmpl:
        try:
            return tmpl.format(**ctx)
        except (KeyError, IndexError, ValueError):
            pass
    return (f"Wazuh rule {rule_id} (level {level}) fired on `{host}` from source `{ctx['srcip']}`. "
            f"Review the raw event below and correlate with other activity from the same source.")


def _is_private(ip: str) -> bool:
    ip = ip or ""
    return (ip.startswith(("10.", "192.168.", "127.")) or
            any(ip.startswith(f"172.{n}.") for n in range(16, 32)))


def is_attack(alert: dict) -> bool:
    """True when the alert's rule is tagged as an attack, not a benign twin."""
    return "attack" in (alert.get("rule", {}).get("groups", []) or [])


def merge_key(alert: dict) -> str:
    """The external, attacker-controlled IP that identifies one incident, or '' if none.
    Inbound attacks key on the source IP; outbound attacks (c2/exfil) run from the internal
    host, so they key on the external destination IP."""
    data = alert.get("data", {})
    for ip in (data.get("srcip"), data.get("dstip")):
        if ip and not _is_private(ip):
            return ip
    return ""


STATE_DIR = os.environ.get("W2THIVE_STATE_DIR", "/tmp/w2thive-state")
INCIDENT_TTL = int(os.environ.get("W2THIVE_INCIDENT_TTL", "900"))  # seconds


def _state_path(ip: str) -> str:
    safe = ip.replace(":", "_").replace("/", "_")
    return os.path.join(STATE_DIR, safe)


def lookup_case(ip: str, now: float = None) -> str:
    """The case id remembered for this IP if its entry is within the TTL, else ''."""
    now = _time.time() if now is None else now
    try:
        with open(_state_path(ip), encoding="utf-8") as fh:
            ts_str, case_id = fh.read().strip().split(" ", 1)
        ts = float(ts_str)
    except (OSError, ValueError):
        return ""
    return case_id if (now - ts) <= INCIDENT_TTL else ""


def remember_case(ip: str, case_id: str, now: float = None) -> None:
    """Record the case id for this IP, stamped with the current time."""
    now = _time.time() if now is None else now
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = _state_path(ip) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(f"{now} {case_id}")
    os.replace(tmp, _state_path(ip))


@contextlib.contextmanager
def ip_lock(ip: str):
    """Serialise the get-or-create for one IP across concurrent integrator runs."""
    os.makedirs(STATE_DIR, exist_ok=True)
    fh = open(_state_path(ip) + ".lock", "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def observables(data: dict, agent_name: str) -> list:
    obs = []

    def add(dtype, val, msg, ioc=False):
        if val:
            obs.append({"dataType": dtype, "data": str(val), "message": msg, "ioc": ioc})

    add("ip", data.get("srcip"), "source address", ioc=not _is_private(data.get("srcip")))
    url = data.get("url")
    add("url", url, "request path / embedded link")
    if url and "host=" in url:
        host = url.split("host=", 1)[1].split("&", 1)[0].split(";", 1)[0]
        if host and "." in host:
            add("domain", host, "outbound destination host", ioc=True)
    elif url and url.startswith(("http://", "https://")):
        dom = url.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]
        if dom and "." in dom:
            add("domain", dom, "embedded link domain", ioc=True)
    add("user-agent", data.get("user_agent"), "client user-agent")
    add("other", data.get("dstuser"), "account seen in the triggering event")
    # Mail-gateway fields (phishing / clean email alerts)
    verdict = data.get("verdict")
    is_phish = verdict in ("phishing", "suspicious")
    add("mail", data.get("mail_from"), "email sender", ioc=is_phish)
    add("mail", data.get("mail_to"), "email recipient")
    att = data.get("attachment")
    if att and str(att).lower() != "none":
        add("filename", att, "email attachment", ioc=is_phish)
    sha256 = data.get("sha256")
    if sha256 and str(sha256).lower() != "none":
        add("hash", sha256, "attachment sha256", ioc=is_phish)
    md5 = data.get("md5")
    if md5 and str(md5).lower() != "none":
        add("hash", md5, "attachment md5", ioc=is_phish)
    fpath = (data.get("file") or {}) if isinstance(data.get("file"), dict) else {}
    add("filename", fpath.get("path") or data.get("path"), "file written on the host", ioc=True)
    # Data-transfer destination (backup / exfil): an external destination is the IOC.
    dstip = data.get("dstip")
    if dstip:
        add("ip", dstip, "transfer destination", ioc=not _is_private(dstip))
    dhost = data.get("dst_host")
    if dhost and dhost != "-":
        add("domain" if "." in dhost else "fqdn", dhost, "transfer destination host", ioc=("." in dhost))
    add("fqdn", agent_name, "affected host")
    return obs


def evidence(rule_id: str, data: dict) -> list:
    """Markdown lines describing the outcome the alert actually recorded, from decoded fields."""
    status = data.get("id")
    try:
        nbytes = int(data.get("bytes", 0))
    except (TypeError, ValueError):
        nbytes = 0
    if rule_id in ("100110",):  # SQLi
        if status == "200":
            return [f"- Endpoint returned **HTTP 200 with {nbytes} bytes** to the injected request, "
                    "so the injection returned data (successful extraction or auth bypass)."]
        if status == "500":
            return ["- Endpoint returned **HTTP 500** (database error), confirming the parameter is "
                    "injectable even though this payload broke the query."]
    if rule_id in ("100150",):  # path traversal
        if status == "200":
            return [f"- Endpoint returned **HTTP 200 with {nbytes} bytes**, so the traversal served "
                    "the requested file contents."]
        return ["- Endpoint did not return the file for this request; the traversal pattern is still "
                "a confirmed attempt."]
    if rule_id in ("100130",):  # web shell execution
        return [f"- The uploaded script at `{data.get('url')}` was requested from `{data.get('srcip')}`; "
                f"the server returned **HTTP {status}**. Inspect the command in the query string."]
    if rule_id in ("100131",):  # web shell upload
        return ["- A file was uploaded to the web upload endpoint; retrieve it from the host, inspect it "
                "for web-shell code, then look for a request that invokes it from the same source."]
    if rule_id in ("100140",):  # C2 beacon
        return [f"- The source host made repeated outbound connections to `{data.get('dst_host')}` "
                f"(`{data.get('dstip')}`) at a regular interval with small payloads, a beacon pattern."]
    if rule_id in ("100142",):  # exfil
        b = nbytes
        size = f"{b/1e9:.1f} GB" if b >= 1_000_000_000 else f"{b/1e6:.0f} MB"
        return [f"- **{size}** left the host for external destination `{data.get('dst_host')}` "
                f"(`{data.get('dstip')}`) using `{data.get('user_agent')}`."]
    if rule_id in ("100170",):  # phishing
        return [f"- Attachment `{data.get('attachment')}` has sha256 `{data.get('sha256')}`; look it "
                f"up. Embedded link `{data.get('url')}`; check its reputation.",
                "- The gateway flagged the message as suspicious but did not classify it; the hash and "
                "link reputation decide."]
    if rule_id == "100141":  # CDN callout (benign twin of C2)
        return [f"- The host made an outbound proxy connection to `{data.get('dst_host')}` "
                f"(`{data.get('dstip')}`), categorised by the proxy as a CDN destination."]
    if rule_id == "100143":  # backup transfer (benign twin of exfil)
        size = f"{nbytes/1e9:.1f} GB" if nbytes >= 1_000_000_000 else f"{nbytes/1e6:.0f} MB"
        return [f"- **{size}** transferred from the host to `{data.get('dst_host')}` "
                f"(`{data.get('dstip')}`) using `{data.get('user_agent')}`."]
    if rule_id == "100121":  # successful web login (admin decoy / SQLi auth-bypass)
        return [f"- A successful authentication was recorded for the submitted account from `{data.get('srcip')}`."]
    if rule_id == "100151":  # heavy crawler (benign twin of recon)
        return [f"- High request volume from `{data.get('srcip')}` using the user-agent `{data.get('user_agent')}`."]
    if rule_id == "100161":  # successful SSH login (compromise or admin decoy)
        return [f"- A successful SSH login for `{data.get('dstuser') or data.get('user') or 'the account'}` from `{data.get('srcip')}`."]
    if rule_id in ("100162", "100163"):  # brute-force breakthrough (web / SSH)
        return [f"- A successful login from `{data.get('srcip')}` followed the failed attempts from the "
                "same source - the brute force broke through. Identify the account that fell, reset it, "
                "and hunt this source's activity after the successful login."]
    return []


def build_case(alert: dict):
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    if "syscheck" in alert:
        data = {**data, "file": {"path": alert["syscheck"].get("path")}}
    rule_id = str(rule.get("id", "0"))
    level = int(rule.get("level", 0))
    srcip = data.get("srcip", "n/a")
    ts = alert.get("timestamp", "")
    agent_name = alert.get("agent", {}).get("name", "n/a")
    # The affected host is the log's own hostname when the source carries one (SSH auth.log,
    # mail gateway), otherwise the Wazuh agent that reported it.
    host_name = alert.get("predecoder", {}).get("hostname") or agent_name
    # Drop the attack/benign group labels: the case must not hand the analyst a verdict.
    groups = [g for g in (rule.get("groups", []) or []) if g not in ("attack", "benign")]
    mitre = MITRE.get(rule_id)

    # A brute force sprays many usernames, but the composite alert only carries the single
    # event that crossed the threshold — so don't present that one account as "the target".
    if rule_id in ("100120", "100160"):
        target = "multiple accounts (credential spray)"
    elif rule_id in ("100142", "100143"):
        target = data.get("dst_host") or data.get("dstip") or "n/a"
    else:
        target = data.get("url") or data.get("dstuser") or data.get("user") or data.get("mail_to") or "n/a"

    tags = ["wazuh", f"rule:{rule_id}", f"level:{level}"] + list(groups)
    if mitre:
        tags.append(f"mitre:{mitre[0]}")

    lines = [
        f"## {rule.get('description', 'Wazuh detection')}",
        "",
        "### Summary",
        summarize(rule_id, data, level, host_name),
        "",
        f"Detected by **Wazuh rule {rule_id}** (level {level}) on host `{host_name}`.",
        "",
        "| | |",
        "|---|---|",
        f"| Source IP | `{srcip}` |",
        f"| Affected host | `{host_name}` |",
        f"| Target | `{target}` |",
        f"| When | {ts} |",
    ]
    if alert.get("id"):
        lines.append(f"| Wazuh alert | [{alert['id']}]({alert_link(alert['id'])}) |")
    if mitre:
        lines.append(f"| MITRE ATT&CK | {mitre[0]} — {mitre[1]} |")
    ev = evidence(rule_id, data)
    if ev:
        lines += ["", "### Evidence"] + ev
    lines += [
        "",
        "### What to check",
        f"- Hunt this source in the SIEM: search `data.srcip:{srcip}` over the last 24h to see the full burst.",
        f"- Reputation of the source IP `{srcip}` (AbuseIPDB).",
        f"- {HINTS.get(rule_id, 'Correlate with other activity from the same source.')}",
        "",
        "### Raw event",
        "```",
        (alert.get("full_log", "") or "")[:1000],
        "```",
    ]

    case = {
        "title": rule.get("description", f"Wazuh rule {rule_id}"),
        "description": "\n".join(lines),
        "severity": severity_from_level(level),
        "tags": tags,
        "tlp": 2,
        "pap": 2,
    }
    return case, observables(data, host_name)


def _get(url: str, api_key: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


def _patch(url: str, api_key: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="PATCH")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


def _post(url: str, api_key: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


def notify_n8n(case_id: str, case: dict) -> None:
    """Fire the n8n triage workflow for a freshly created case.

    The payload mirrors TheHive's native case webhook, so the n8n workflow's
    "Extract case" node reads the same `body.object.{_id,title,description}`
    fields whether the trigger comes from here or from TheHive itself. Best
    effort: a failure here must never fail case creation.
    """
    if not N8N_WEBHOOK_URL:
        return
    payload = {
        "operation": "Creation",
        "objectType": "case",
        "object": {
            "_id": case_id,
            "id": case_id,
            "title": case.get("title"),
            "description": case.get("description"),
            "severity": case.get("severity"),
            "tags": case.get("tags"),
        },
    }
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(N8N_WEBHOOK_URL, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10):
            pass
        sys.stderr.write(f"custom-w2thive: notified n8n for case {case_id}\n")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"custom-w2thive: n8n notify failed: {exc}\n")


def create_case(base_url: str, api_key: str, case: dict, obs: list, ip: str) -> str:
    """Create the case, tag it with the attacker IP, attach observables and a triage task.
    Returns the new case id. Does not trigger n8n; the caller decides when to triage."""
    base = base_url.rstrip("/")
    if ip:
        case = {**case, "tags": list(case.get("tags", [])) + [f"attacker-ip:{ip}"]}
    created = _post(f"{base}/api/v1/case", api_key, case)
    case_id = created.get("_id") or created.get("id")
    sys.stderr.write(f"custom-w2thive: created case {case_id}\n")
    for ob in obs:
        try:
            _post(f"{base}/api/v1/case/{case_id}/observable", api_key, ob)
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            sys.stderr.write(f"custom-w2thive: observable {ob.get('data')} failed: {exc}\n")
    try:
        _post(f"{base}/api/v1/case/{case_id}/task", api_key, {
            "title": "Triage & verdict",
            "description": ("Enrich the observables (source-IP reputation first), decide "
                            "true positive / false positive, and record the verdict."),
            "group": "triage",
        })
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        sys.stderr.write(f"custom-w2thive: task create failed: {exc}\n")
    return case_id


def append_to_case(base_url: str, api_key: str, case_id: str, case: dict, obs: list) -> None:
    """Append a second detection to an open case: a new description section, its observables,
    and the higher severity of the two."""
    base = base_url.rstrip("/")
    section = "\n\n---\n\n### Additional detection\n\n" + case["description"]
    try:
        current = _get(f"{base}/api/v1/case/{case_id}", api_key)
        _patch(f"{base}/api/v1/case/{case_id}", api_key, {
            "description": (current.get("description", "") or "") + section,
            "severity": max(int(current.get("severity", 1) or 1), int(case.get("severity", 1))),
        })
        sys.stderr.write(f"custom-w2thive: appended detection to case {case_id}\n")
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        sys.stderr.write(f"custom-w2thive: append to case {case_id} failed: {exc}\n")
    for ob in obs:
        try:
            _post(f"{base}/api/v1/case/{case_id}/observable", api_key, ob)
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            sys.stderr.write(f"custom-w2thive: observable {ob.get('data')} failed: {exc}\n")


def route_alert(base_url: str, api_key: str, alert: dict) -> None:
    """Create a case, or fold this alert into the open case for its attacker IP, then trigger
    triage once per case.

    An attack alert with an external key opens or extends the incident case for that IP. A
    benign-shaped alert (a successful login, a clean callout) with an external key merges only
    when an incident is ALREADY open for that IP: that is the brute force's own success landing,
    which must join the attack case rather than sit in its own dismissable ticket. A benign alert
    with no open incident, or no external key at all, stays a standalone case, so a shared clean
    IP (the crawler/newsletter benign address) does not cluster unrelated benign events."""
    case, obs = build_case(alert)
    ip = merge_key(alert)
    if not ip:
        case_id = create_case(base_url, api_key, case, obs, "")
        notify_n8n(case_id, case)
        return
    action = None
    case_id = None
    with ip_lock(ip):
        existing = lookup_case(ip)
        if existing:
            append_to_case(base_url, api_key, existing, case, obs)
            action = "append"
        elif is_attack(alert):
            case_id = create_case(base_url, api_key, case, obs, ip)
            remember_case(ip, case_id)
            action = "create"
        else:
            case_id = create_case(base_url, api_key, case, obs, "")
            action = "standalone"
    if action == "create":
        _time.sleep(N8N_TRIGGER_DELAY)
        notify_n8n(case_id, case)
    elif action == "standalone":
        notify_n8n(case_id, case)


def main() -> int:
    if len(sys.argv) < 4:
        sys.stderr.write("custom-w2thive: expected alert_file, api_key, hook_url\n")
        return 1
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        with open(alert_file, "r", encoding="utf-8") as fh:
            alert = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"custom-w2thive: cannot read alert: {exc}\n")
        return 1
    try:
        route_alert(hook_url, api_key, alert)
    except urllib.error.HTTPError as exc:
        sys.stderr.write(f"custom-w2thive: HTTP {exc.code}: {exc.read()[:300]!r}\n")
        return 1
    except urllib.error.URLError as exc:
        sys.stderr.write(f"custom-w2thive: cannot reach TheHive: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
