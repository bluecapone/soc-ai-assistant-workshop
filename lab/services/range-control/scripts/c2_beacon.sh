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
n="$(rint 12 24)"
echo "C2 beacon: ${WEBAPP_IP} -> ${dom} (${dst}:${port}) ${n}x, family=${fam}"
# Emit the burst at the current time. Each line independently matches rule 100140 (single-event on
# an uncategorised destination); ignore=60 on the rule collapses the burst into one case. The burst
# of N identical small callouts to one uncategorised destination reads as a realistic beacon in the
# log the student inspects.
for ((i=1; i<=n; i++)); do
  bytes="$(rint 180 340)"   # small, consistent beacon payloads
  proxy_line "$WEBAPP_IP" "$dst" "$dom" "$port" "$bytes" "$ua" uncategorized
done
