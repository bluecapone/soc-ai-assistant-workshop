#!/usr/bin/env bash
# Attack (rule 100140): the compromised web host beacons out through the corporate proxy to a real
# command-and-control server (a ThreatFox botnet_cc indicator from iocs.csv). Uncategorised
# destination, small consistent payloads. Rule 100140 fires on any uncategorised outbound egress
# from the internal host; the analyst confirms the destination via external OSINT.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ua="$(pick 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0' curl/8.5.0 'Go-http-client/1.1')"

if [ -n "${MALICIOUS_DEST_IP:-}" ]; then
  dst="$MALICIOUS_DEST_IP"
else
  IFS='|' read -r dst fam _s <<<"$(pick_ioc c2 ip)"
fi
IFS='|' read -r dom _fl _fs <<<"$(pick_ioc c2 domain)"
: "${dst:=154.91.63.98}"; : "${dom:=$dst}"; : "${fam:=unknown}"
port="$(pick 443 8080 8443 8084 53)"
# Live burst to trip the frequency rule 100140 now and raise the case. Like the recon/brute rules
# (which burst 45-130 for a frequency of 5-6), the live analysisd needs the burst well above the
# nominal frequency=5 to fire reliably, so keep it generous. The realistic cadence is backfilled below.
n="$(rint 14 18)"
echo "C2 beacon: ${WEBAPP_IP} -> ${dom} (${dst}:${port}) ${n}x live + ~30min backfill, family=${fam}"
for ((i=1; i<=n; i++)); do
  bytes="$(rint 180 340)"   # small, consistent beacon payloads
  proxy_line "$WEBAPP_IP" "$dst" "$dom" "$port" "$bytes" "$ua" uncategorized
done
# Backfill the beacon's history: spaced callouts to the SAME destination over the last ~30 min
# (~60s +/- jitter), written straight into the indexer so the SIEM shows a periodic beacon instead
# of one clustered burst. Anchor rule 100148 (not forwarded), so it raises no extra case. Best-effort.
python3 "$(dirname "$0")/beacon_backfill.py" \
  --rule 100148 --cat uncategorized --level 3 \
  --description "Outbound proxy connection to uncategorised destination ${dom}" \
  --src-ip "$WEBAPP_IP" --dst-ip "$dst" --dst-host "$dom" --port "$port" \
  --ua "$ua" --min-bytes 180 --max-bytes 340 || true
