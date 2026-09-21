#!/usr/bin/env python3
"""
Backfill a realistic beacon *cadence* straight into the indexer.

The console fires a beacon as a burst (all callouts in the same second), which trips the
detection rule fine but does not look like a real beacon when a student pivots on the
destination in the SIEM — every callout shares one timestamp. This writes N callout events
directly to the indexer (the same path soc-noise and breadcrumbs.py use) with @timestamps
spread back over a window at a ~60s ± jitter interval, so the destination shows a periodic
beacon stretching back in time. It creates NO case: the events are the anchor rule
(100148 C2 / 100149 CDN), which is not on the integrator forward list. The short live
proxy.log burst the calling script still emits is what trips 100140/100141 and raises the case.

Best-effort: a slow or missing indexer never fails the attack (the caller ignores errors).
Fields mirror the proxy decoder exactly (data.dstport, not data.port — data.port is an
object in the Wazuh template and a scalar there gets the whole doc rejected).
"""

import argparse
import base64
import json
import random
import ssl
import urllib.request
from datetime import datetime, timedelta, timezone
import os

AGENT = {"name": "wazuh.manager", "id": "000"}


def _syslog_ts(dt):
    # "Sep 21 09:11:16" — %e is space-padded day, matching the proxy log format.
    return dt.strftime("%b %e %H:%M:%S")


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def _index_name(dt):
    return f"wazuh-alerts-4.x-{dt.strftime('%Y.%m.%d')}"


def _event(dt, args):
    bytes_ = random.randint(args.min_bytes, args.max_bytes)
    pid = random.randint(1000, 9999)
    syslog = _syslog_ts(dt)
    full_log = (
        f'{syslog} proxy-01 proxy[{pid}]: src={args.src_ip} dst={args.dst_ip} '
        f'dst_host={args.dst_host} port={args.port} method=CONNECT bytes={bytes_} '
        f'ua="{args.ua}" cat={args.cat} action=allowed'
    )
    return {
        "timestamp": _iso(dt),
        "@timestamp": _iso(dt),
        "agent": AGENT,
        "manager": {"name": "wazuh.manager"},
        "rule": {"id": args.rule, "level": args.level, "description": args.description,
                 "groups": ["bankweb"], "firedtimes": 1, "mail": False},
        "decoder": {"name": "proxy"},
        "predecoder": {"program_name": "proxy", "timestamp": syslog, "hostname": "proxy-01"},
        "location": "/var/log/host/proxy.log",
        "data": {"srcip": args.src_ip, "dstip": args.dst_ip, "dst_host": args.dst_host,
                 "dstport": str(args.port), "method": "CONNECT", "bytes": str(bytes_),
                 "user_agent": args.ua, "cat": args.cat, "action": "allowed"},
        "full_log": full_log,
        "id": f"{dt.timestamp():.6f}",
    }


def _spread(args):
    """Timestamps from ~now back over --span seconds, stepping by min..max-gap each time."""
    out, t = [], datetime.now(timezone.utc) - timedelta(seconds=random.randint(20, 60))
    floor = datetime.now(timezone.utc) - timedelta(seconds=args.span)
    while t > floor:
        out.append(t)
        t = t - timedelta(seconds=random.randint(args.min_gap, args.max_gap))
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rule", required=True)          # 100148 (C2 anchor) / 100149 (CDN anchor)
    p.add_argument("--cat", required=True)           # uncategorized / cdn
    p.add_argument("--level", type=int, default=3)
    p.add_argument("--description", default="Outbound proxy connection (backfilled beacon cadence)")
    p.add_argument("--src-ip", required=True)
    p.add_argument("--dst-ip", required=True)
    p.add_argument("--dst-host", required=True)
    p.add_argument("--port", required=True)
    p.add_argument("--ua", default="curl/8.5.0")
    p.add_argument("--min-bytes", type=int, default=180)
    p.add_argument("--max-bytes", type=int, default=340)
    p.add_argument("--span", type=int, default=1800)   # 30 min
    p.add_argument("--min-gap", type=int, default=45)  # ~60s ± jitter
    p.add_argument("--max-gap", type=int, default=90)
    args = p.parse_args()

    times = _spread(args)
    if not times:
        return

    lines = []
    for dt in times:
        lines.append(json.dumps({"index": {"_index": _index_name(dt)}}))
        lines.append(json.dumps(_event(dt, args)))
    body = ("\n".join(lines) + "\n").encode()

    url = os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200")
    user = os.environ.get("INDEXER_USER", "admin")
    pw = os.environ.get("INDEXER_PASS", "brucon2026")
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(f"{url}/_bulk", data=body, method="POST",
                                 headers={"Content-Type": "application/x-ndjson",
                                          "Authorization": f"Basic {token}"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        urllib.request.urlopen(req, timeout=8, context=ctx).read()
        print(f"  backfill  {len(times)} spaced callouts to {args.dst_host} over {args.span // 60}min")
    except Exception as exc:
        print(f"  backfill  skipped ({exc})")


if __name__ == "__main__":
    main()
