#!/usr/bin/env bash
# get_case.sh <case-id>   Read one TheHive case: title, tags, description, source IP, observables. Read-only.
set -euo pipefail
: "${THEHIVE_URL:?export THEHIVE_URL first}" "${THEHIVE_APIKEY:?export THEHIVE_APIKEY first}"
CASE_ID=${1:?usage: get_case.sh <case-id like ~123456>}
AUTH=(-H "Authorization: Bearer $THEHIVE_APIKEY")
CASE=$(curl -sSf "$THEHIVE_URL/api/v1/case/$CASE_ID" "${AUTH[@]}")
OBS=$(curl -sSf -X POST "$THEHIVE_URL/api/v1/query" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"query":[{"_name":"getCase","idOrName":"'"$CASE_ID"'"},{"_name":"observables"}]}' || echo '[]')
jq -n --argjson case "$CASE" --argjson obs "$OBS" '{
  title: $case.title, tags: $case.tags, description: $case.description,
  srcip: (($case.description // "") | (capture("\\| Source IP \\| `(?<ip>[^`]+)` \\|") // {ip:null}).ip),
  observables: [$obs[] | {dataType, data}]
}'
