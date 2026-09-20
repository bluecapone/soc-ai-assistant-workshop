"""
SOC noise generator.

Keeps the Wazuh SIEM looking like a real, busy public web server: benign traffic from
the wider internet hitting the bank's public site. It backfills a few hours of history
on start, then trickles live events.

Design choice: events are written DIRECTLY into the indexer, not through the target and
the detection rules. That keeps the noise completely separate from the attack pipeline,
so it can never steal an attack's rule match or open a spurious case. rule.id 100200 is
not in the integrator's forward list, so nothing here reaches TheHive.
"""

import os
import random
import time
from datetime import datetime, timedelta, timezone

import requests
import urllib3

import events

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER = os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200")
USER = os.environ.get("INDEXER_USER", "admin")
PW = os.environ.get("INDEXER_PASS", "brucon2026")
BACKFILL_HOURS = float(os.environ.get("BACKFILL_HOURS", "4"))
BACKFILL_COUNT = int(os.environ.get("BACKFILL_COUNT", "900"))
TRICKLE_SECONDS = float(os.environ.get("TRICKLE_SECONDS", "3"))

AUTH = (USER, PW)

# Benign visitor addresses come from the shared threat-intel benign ranges (RFC 5737
# documentation nets), so a live AbuseIPDB lookup on any of them returns "no reputation".
random.seed()
BENIGN_RANGES_FILE = os.environ.get("BENIGN_RANGES_FILE", "/app/threat-intel/benign-ranges.txt")


def _load_benign_prefixes():
    prefixes = []
    try:
        with open(BENIGN_RANGES_FILE) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                octets = line.split("/")[0].split(".")
                if len(octets) == 4:
                    prefixes.append(".".join(octets[:3]))
    except OSError:
        pass
    return prefixes or ["35.235.240"]


BENIGN_PREFIXES = _load_benign_prefixes()
# The console's attacker/benign IPs must NEVER appear in the noise, so a student only
# sees them from their own actions.
EXCLUDE_IPS = {ip.strip() for ip in os.environ.get("EXCLUDE_IPS", "").split(",") if ip.strip()}


def rand_visitor_ip():
    for _ in range(12):
        ip = f"{random.choice(BENIGN_PREFIXES)}.{random.randint(1, 254)}"
        if ip not in EXCLUDE_IPS:
            return ip
    return ip

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
]
PAGES = ["/", "/", "/", "/accounts", "/help", "/branches", "/contact", "/rates"]
PRODUCTS = ["savings", "current account", "credit card", "mortgage", "loan", "isa", "pension"]
CUSTOMERS = ["emma.wilson", "liam.murphy", "sofia.rossi", "daniel.kim",
             "olivia.martin", "noah.schmidt", "aisha.khan"]


def _ts_apache(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")


def make_event(dt: datetime) -> dict:
    """One benign public-web event as a Wazuh-shaped alert doc."""
    ip = rand_visitor_ip()
    ua = random.choice(UAS)
    iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    kind = random.random()

    if kind < 0.20:
        # customer logs in successfully
        user = random.choice(CUSTOMERS)
        full = f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}+0000 authresult=success user={user} src_ip={ip}"
        return _doc(iso, ip, level=3, desc=f"Customer login from {ip}",
                    groups=["bankweb", "web", "ambient", "authentication_success"],
                    decoder="bankweb-auth", location="/var/log/bank-web/auth.log",
                    data={"srcip": ip, "user": user, "authresult": "success"}, full_log=full)

    if kind < 0.45:
        path = f"/search?q={random.choice(PRODUCTS).replace(' ', '%20')}"
    else:
        path = random.choice(PAGES)
    status = 200 if random.random() > 0.06 else 404  # the occasional dead link, no burst
    nbytes = random.randint(180, 4200)
    # Same tagged shape and field set the bankweb-access decoder emits, so noise and real
    # events look identical in the dashboard (see lab/platform/wazuh/local_decoder.xml).
    full = f'bankweb {ip} - [{_ts_apache(dt)}] "GET {path} HTTP/1.1" {status} {nbytes} "{ua}"'
    desc = f"Public web request from {ip}" if status == 200 else f"Public web 404 from {ip}"
    return _doc(iso, ip, level=3 if status == 200 else 4, desc=desc,
                groups=["bankweb", "web", "ambient"],
                decoder="bankweb-access", location="/var/log/bank-web/access.log",
                data={"srcip": ip, "method": "GET", "url": path, "protocol": "HTTP/1.1",
                      "id": str(status), "bytes": str(nbytes), "user_agent": ua},
                full_log=full)


def make_host_event(dt: datetime) -> dict:
    """One benign paper-host event, chosen at random across the internal hosts."""
    iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    pick = random.random()
    if pick < 0.20:
        wks, wks_ip = random.choice(events.WORKSTATIONS)
        return events.dc_logon(iso, random.choice(events.STAFF), wks, wks_ip)
    if pick < 0.40:
        return events.db_query(iso, "svc_webapp", random.choice(["SELECT", "SELECT", "INSERT"]),
                               random.randint(1, 800), "10.20.0.10")
    if pick < 0.52:
        _wks, wks_ip = random.choice(events.WORKSTATIONS)
        return events.fs_access(iso, random.choice(events.STAFF),
                                random.choice(["finance", "shared", "hr", "it"]),
                                random.choice(["/reports/Q3.xlsx", "/policies/handbook.pdf",
                                               "/tickets/INC-3312.txt"]),
                                random.choice(["open", "open", "close"]), wks_ip)
    if pick < 0.64:
        sender = random.choice(["news@vendor.example", "billing@saas.example",
                                "no-reply@calendar.example"])
        to = f"{random.choice(events.STAFF)}@bankofwonderland.example"
        return events.mail_flow(iso, sender, to, rand_visitor_ip())
    if pick < 0.76:
        _wks, wks_ip = random.choice(events.WORKSTATIONS)
        return events.proxy_browse(iso, wks_ip,
                                   random.choice(["docs.python.org", "portal.office.example",
                                                  "news.example", "vendor-status.example"]),
                                   random.choice(["technology", "business", "news"]),
                                   random.randint(400, 9000))
    if pick < 0.86:
        return events.vpn_session(iso, random.choice(events.STAFF), rand_visitor_ip(),
                                  random.choice(["connect", "connect", "disconnect"]))
    if pick < 0.96:
        wks, _ip = random.choice(events.WORKSTATIONS)
        return events.edr_event(iso, wks, random.choice(events.STAFF),
                                random.choice(["logon", "logon", "process"]),
                                random.choice(["interactive", "outlook.exe", "chrome.exe",
                                               "teams.exe"]))
    return events.backup_job(iso, "Nightly-CoreBank",
                             random.choice(["Success", "Success", "Warning"]),
                             random.randint(200, 900) * 1048576)


def _doc(iso, ip, level, desc, groups, decoder, location, data, full_log) -> dict:
    return {
        "timestamp": iso,
        "@timestamp": iso,
        "agent": {"name": "wazuh.manager", "id": "000"},
        "manager": {"name": "wazuh.manager"},
        "rule": {"id": "100200", "level": level, "description": desc,
                 "groups": groups, "firedtimes": 1, "mail": False},
        "decoder": {"name": decoder},
        "location": location,
        "data": data,
        "full_log": full_log,
        "id": f"{time.time():.6f}",
    }


def index_name(dt: datetime) -> str:
    return f"wazuh-alerts-4.x-{dt.strftime('%Y.%m.%d')}"


def bulk(events) -> None:
    lines = []
    for dt, doc in events:
        lines.append(f'{{"index":{{"_index":"{index_name(dt)}"}}}}')
        lines.append(__import__("json").dumps(doc))
    body = "\n".join(lines) + "\n"
    r = requests.post(f"{INDEXER}/_bulk", data=body, auth=AUTH, verify=False,
                      headers={"Content-Type": "application/x-ndjson"}, timeout=30)
    r.raise_for_status()


def wait_for_indexer() -> None:
    for _ in range(120):
        try:
            if requests.get(f"{INDEXER}/", auth=AUTH, verify=False, timeout=5).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(3)
    raise SystemExit("soc-noise: indexer never came up")


def ensure_template() -> None:
    # soc-noise writes straight into wazuh-alerts-4.x-* via _bulk, which auto-creates the
    # daily index. Without the Wazuh field template applied first, string fields fall back
    # to the dynamic "text" mapping, and the dashboard's sort/aggregate on manager.name (and
    # other fields) fails with "Text fields are not optimised...". Applying the template here
    # — before the first write and before the manager's filebeat boots — guarantees every
    # index gets the correct keyword mappings.
    path = os.environ.get("TEMPLATE_FILE", "/app/wazuh-template.json")
    if not os.path.exists(path):
        print(f"soc-noise: no template at {path}; skipping (dashboard aggregations may fail)", flush=True)
        return
    try:
        with open(path) as fh:
            body = fh.read()
        r = requests.put(f"{INDEXER}/_template/wazuh-alerts", data=body, auth=AUTH, verify=False,
                         headers={"Content-Type": "application/json"}, timeout=30)
        print(f"soc-noise: applied wazuh-alerts template ({r.status_code})", flush=True)
    except (requests.RequestException, OSError) as exc:
        print(f"soc-noise: template apply failed: {exc}", flush=True)


def backfill() -> None:
    now = datetime.now(timezone.utc)
    span = timedelta(hours=BACKFILL_HOURS)
    docs = []
    for _ in range(BACKFILL_COUNT):
        dt = now - span * random.random()
        doc = make_host_event(dt) if random.random() < 0.35 else make_event(dt)
        docs.append((dt, doc))
    for i in range(0, len(docs), 200):
        bulk(docs[i:i + 200])
    print(f"soc-noise: backfilled {len(docs)} events over the last {BACKFILL_HOURS}h", flush=True)


def trickle() -> None:
    print("soc-noise: live trickle started", flush=True)
    while True:
        now = datetime.now(timezone.utc)
        batch = [(now, make_host_event(now) if random.random() < 0.35 else make_event(now))
                 for _ in range(random.randint(1, 3))]
        try:
            bulk(batch)
        except requests.RequestException as exc:
            print(f"soc-noise: trickle error {exc}", flush=True)
        time.sleep(TRICKLE_SECONDS)


if __name__ == "__main__":
    wait_for_indexer()
    ensure_template()
    backfill()
    trickle()
