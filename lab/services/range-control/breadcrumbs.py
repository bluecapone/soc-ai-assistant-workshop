"""
Incident breadcrumbs: cross-host corroboration written into the indexer when a student
fires the buttons that have a wider story. exfil shows a database dump and a file-share
bulk read; phishing shows the finance user opening the mail and authenticating; the SSH
compromise shows the account moving laterally to the domain controller.

The ids 100221 to 100225 are absent from the integrator forward list, so a breadcrumb
never creates its own case. The write is best-effort so a slow or missing indexer never
breaks the attack, which runs through the separate file-based detection path.
"""

import base64
import json
import os
import ssl
import time
import urllib.request
from datetime import datetime, timezone

INDEXER_URL = os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200")
INDEXER_USER = os.environ.get("INDEXER_USER", "admin")
INDEXER_PASS = os.environ.get("INDEXER_PASS", "brucon2026")

# The finance user and workstation the phishing story lands on.
PHISH_USER = "sarah.mitchell"
PHISH_WKS = "workstation-finance-01"
PHISH_WKS_IP = "10.20.20.11"
# The web host's domain service account, used for the lateral move to the DC.
COMPROMISED_ACCOUNT = "svc_webapp"
WEBAPP_IP = "10.20.0.10"


def _doc(iso, rule_id, level, desc, groups, decoder, location, data, full_log):
    return {
        "timestamp": iso,
        "@timestamp": iso,
        "agent": {"name": "wazuh.manager", "id": "000"},
        "manager": {"name": "wazuh.manager"},
        "rule": {"id": rule_id, "level": level, "description": desc,
                 "groups": groups, "firedtimes": 1, "mail": False},
        "decoder": {"name": decoder},
        "location": location,
        "data": data,
        "full_log": full_log,
        "id": f"{time.time():.6f}",
    }


def breadcrumb_docs(button_id, iso):
    """The corroborating documents for a fired button. Empty when the button has none."""
    if button_id == "exfil":
        return [
            _doc(iso, "100221", 6, "Large database export by the web service account",
                 ["database", "exfiltration"], "postgresql",
                 "/var/log/host/database-01/postgresql.log",
                 {"host": "database-01", "db_user": "svc_webapp", "database": "corebank",
                  "statement_kind": "COPY", "rows": "1204338", "src_ip": WEBAPP_IP},
                 "postgres: LOG: statement: COPY (SELECT * FROM customers) TO STDOUT ; rows=1204338"),
            _doc(iso, "100222", 6, "Bulk read of the finance share",
                 ["fileshare", "exfiltration"], "samba",
                 "/var/log/host/fileserver-01/smbd.log",
                 {"host": "fileserver-01", "user": "svc_webapp", "share": "finance",
                  "op": "bulk-read", "files": "842", "src_ip": WEBAPP_IP},
                 "smbd: user=svc_webapp share=finance op=bulk-read files=842 bytes=big"),
        ]
    if button_id == "phishing":
        return [
            _doc(iso, "100223", 5, f"Finance user opened the message on {PHISH_WKS}",
                 ["endpoint", "phishing"], "edr", f"/var/log/host/{PHISH_WKS}/edr.log",
                 {"host": PHISH_WKS, "user": PHISH_USER, "event": "mail-open",
                  "proc": "outlook.exe"},
                 f"edr: host={PHISH_WKS} user={PHISH_USER} event=mail-open proc=outlook.exe"),
            _doc(iso, "100224", 4, f"Domain logon for {PHISH_USER}",
                 ["windows", "authentication_success", "phishing"], "windows-security",
                 "/var/log/host/dc-01/security.log",
                 {"host": "dc-01", "win_event": "4624", "user": PHISH_USER,
                  "logon_type": "3", "src_ip": PHISH_WKS_IP, "workstation": PHISH_WKS,
                  "status": "success"},
                 f"AuthNSvc: EventID=4624 LogonType=3 TargetUserName={PHISH_USER} "
                 f"IpAddress={PHISH_WKS_IP} Workstation={PHISH_WKS} Status=success"),
        ]
    if button_id == "ssh_brute":
        return [
            _doc(iso, "100225", 8,
                 f"Domain logon for {COMPROMISED_ACCOUNT} from web-prod-01",
                 ["windows", "authentication_success", "lateral_movement"], "windows-security",
                 "/var/log/host/dc-01/security.log",
                 {"host": "dc-01", "win_event": "4624", "user": COMPROMISED_ACCOUNT,
                  "logon_type": "3", "src_ip": WEBAPP_IP, "workstation": "web-prod-01",
                  "status": "success"},
                 f"AuthNSvc: EventID=4624 LogonType=3 TargetUserName={COMPROMISED_ACCOUNT} "
                 f"IpAddress={WEBAPP_IP} Workstation=web-prod-01 Status=success"),
        ]
    return []


def _index_name(dt):
    return f"wazuh-alerts-4.x-{dt.strftime('%Y.%m.%d')}"


def emit_breadcrumbs(button_id):
    """Best-effort: POST the button's breadcrumbs to the indexer. Never raises."""
    now = datetime.now(timezone.utc)
    iso = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    docs = breadcrumb_docs(button_id, iso)
    if not docs:
        return
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": _index_name(now)}}))
        lines.append(json.dumps(doc))
    body = ("\n".join(lines) + "\n").encode()
    token = base64.b64encode(f"{INDEXER_USER}:{INDEXER_PASS}".encode()).decode()
    req = urllib.request.Request(f"{INDEXER_URL}/_bulk", data=body, method="POST",
                                 headers={"Content-Type": "application/x-ndjson",
                                          "Authorization": f"Basic {token}"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        urllib.request.urlopen(req, timeout=5, context=ctx).read()
    except Exception:
        pass
