#!/usr/bin/env bash
# Benign twin of c2_beacon (rule 100141): a marketing/analytics tool on an internal workstation calls
# a real CDN through the proxy. Same outbound proxy shape as the C2 beacon, but the source is an
# internal host (not the compromised web server) and the destination is on the proxy CDN allow-list
# (cat=cdn), so it is authorised. The tell is the destination category, not the volume.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ua="$(pick 'MarketingBot/2.1 (+https://acme.example/bot)' 'Mozilla/5.0 (compatible; analytics)' curl/8.5.0)"
cdn="$(pick "${CDN_ALLOWLIST[@]}")"
host="$(pick assets static edge img cache)"."$cdn"
port=443
# Live burst to trip the twin frequency rule 100141 now. Kept generous (well above the nominal
# frequency=5) because the live analysisd needs more than the nominal count, same as the C2 beacon.
n="$(rint 14 18)"
cdnip="203.0.113.$(rint 20 240)"
echo "CDN callout: ${CDN_IP} -> ${host} (${n}x live + ~30min backfill)"
for ((i=1; i<=n; i++)); do
  proxy_line "$CDN_IP" "$cdnip" "$host" "$port" "$(rint 800 6000)" "$ua" cdn
done
# Backfill the same ~30-min cadence as the C2 beacon so the benign twin has the SAME shape on the
# SIEM timeline — the tell stays the destination category (cdn), not a timestamp artefact. Anchor
# rule 100149 (not forwarded), best-effort.
python3 "$(dirname "$0")/beacon_backfill.py" \
  --rule 100149 --cat cdn --level 3 \
  --description "Outbound proxy connection to CDN destination ${host}" \
  --src-ip "$CDN_IP" --dst-ip "$cdnip" --dst-host "$host" --port "$port" \
  --ua "$ua" --min-bytes 800 --max-bytes 6000 || true
