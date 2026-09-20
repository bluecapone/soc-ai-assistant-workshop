#!/usr/bin/env bash
# reputation.sh <ip>   AbuseIPDB when OSINT_API_KEY is set, otherwise the offline list. The output names which one.
set -euo pipefail
IP=${1:?usage: reputation.sh <ip>}
if [ -n "${OSINT_API_KEY:-}" ]; then
  curl -sf -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=$IP" -d maxAgeInDays=90 \
    -H "Key: $OSINT_API_KEY" -H 'Accept: application/json' \
    | jq '{source: "abuseipdb", score: .data.abuseConfidenceScore, reports: .data.totalReports}'
else
  LIST=${LAB_DIR:-lab}/threat-intel/malicious-ips.txt   # run from the workshop folder, or export LAB_DIR
  jq -n --arg ip "$IP" --argjson n "$(grep -cx "$IP" "$LIST" || true)" '{source: "offline list, not live reputation", listed: ($n > 0)}'
fi
