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
n="$(rint 3 6)"
echo "CDN callout: ${CDN_IP} -> ${host} (${n}x)"
for ((i=1; i<=n; i++)); do
  proxy_line "$CDN_IP" "203.0.113.$(rint 20 240)" "$host" "$port" "$(rint 800 6000)" "$ua" cdn
done
