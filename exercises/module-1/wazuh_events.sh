#!/usr/bin/env bash
# wazuh_events.sh <value> [srcip|host]   Last 20 Wazuh events for a source IP (default) or a host, newest first. Read-only.
# The indexer serves a self-signed certificate, hence -k.
set -euo pipefail
: "${WAZUH_URL:?export WAZUH_URL first}"
VALUE=${1:?usage: wazuh_events.sh <ip-or-host> [srcip|host]}
FIELD=data.srcip; [ "${2:-srcip}" = host ] && FIELD=agent.name
curl -sfk -u "${WAZUH_USERNAME:-admin}:${WAZUH_PASSWORD:-brucon2026}" -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":20,"_source":["timestamp","rule.id","rule.level","rule.description","data.srcip","data.url","data.dstuser","agent.name"],"query":{"match":{"'"$FIELD"'":"'"$VALUE"'"}},"sort":[{"timestamp":"desc"}]}' \
  | jq '{total: .hits.total.value, events: [.hits.hits[]._source]}'
