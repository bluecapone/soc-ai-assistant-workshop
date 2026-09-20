"""Snapshot real indicators from abuse.ch into lab/threat-intel/iocs.csv.

Standard library only. Reads ABUSECH_AUTH_KEY from the environment. Writes a
typed, role-tagged CSV the attack scripts read to embed real indicators students look up in external OSINT.

Safety: reads indicator metadata only. Never downloads a malware sample.
"""
import json
import os
import sys
import urllib.parse
import urllib.request

ATTACH_TYPES = {"exe", "dll", "doc", "docx", "xls", "xlsm", "pdf", "js",
                "vbs", "lnk", "iso", "scr", "zip", "rar"}


def _clean(s):
    return (str(s or "").replace(",", " ").replace('"', "").strip()) or "unknown"


def threatfox_rows(data):
    rows = []
    for x in (data.get("data") or []):
        threat_type = x.get("threat_type")
        if threat_type not in ("botnet_cc", "payload_delivery"):
            continue
        if int(x.get("confidence_level") or 0) < 75:
            continue
        t = x.get("ioc_type")
        val = str(x.get("ioc") or "")
        label = _clean(x.get("malware_printable"))
        if threat_type == "botnet_cc":
            if t == "ip:port":
                rows.append({"type": "ip", "value": val.split(":")[0], "role": "c2",
                             "label": label, "source": "ThreatFox"})
            elif t == "domain":
                rows.append({"type": "domain", "value": val, "role": "c2",
                             "label": label, "source": "ThreatFox"})
        elif threat_type == "payload_delivery":
            if t == "domain":
                rows.append({"type": "domain", "value": val, "role": "phishing",
                             "label": label, "source": "ThreatFox"})
            elif t == "url":
                rows.append({"type": "url", "value": val, "role": "phishing",
                             "label": label, "source": "ThreatFox"})
    return rows


def malwarebazaar_rows(data):
    rows = []
    for x in (data.get("data") or []):
        if (x.get("file_type") or "").lower() not in ATTACH_TYPES:
            continue
        sig = x.get("signature")
        if not sig:
            continue
        label = _clean(sig)
        if x.get("sha256_hash"):
            rows.append({"type": "sha256", "value": x["sha256_hash"], "role": "malware",
                         "label": label, "source": "MalwareBazaar"})
        if x.get("md5_hash"):
            rows.append({"type": "md5", "value": x["md5_hash"], "role": "malware",
                         "label": label, "source": "MalwareBazaar"})
    return rows



def to_csv(rows):
    seen, out = set(), ["type,value,role,label,source"]
    for r in rows:
        key = (r["type"], r["value"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f'{r["type"]},{r["value"]},{r["role"]},{r["label"]},{r["source"]}')
    return "\n".join(out) + "\n"


def _post(url, key, payload=None, form=None):
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        ctype = "application/x-www-form-urlencoded"
    else:
        body = json.dumps(payload).encode()
        ctype = "application/json"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Auth-Key", key)
    req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode() or "{}")


def main():
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        sys.stderr.write("set ABUSECH_AUTH_KEY (see lab/.env)\n")
        return 1
    rows = []
    rows += threatfox_rows(_post("https://threatfox-api.abuse.ch/api/v1/", key,
                                 payload={"query": "get_iocs", "days": 3}))
    rows += malwarebazaar_rows(_post("https://mb-api.abuse.ch/api/v1/", key,
                                     form={"query": "get_recent", "selector": "100"}))
    out = os.environ.get("IOCS_OUT",
                         os.path.join(os.path.dirname(__file__), "..", "threat-intel", "iocs.csv"))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(to_csv(rows))
    sys.stderr.write(f"wrote {out} ({len(rows)} rows before dedup)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
