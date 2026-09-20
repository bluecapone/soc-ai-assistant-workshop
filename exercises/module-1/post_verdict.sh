#!/usr/bin/env bash
# post_verdict.sh <case-id>   The one write: the verdict Markdown on stdin becomes one comment on the case.
set -euo pipefail
: "${THEHIVE_URL:?export THEHIVE_URL first}" "${THEHIVE_APIKEY:?export THEHIVE_APIKEY first}"
CASE_ID=${1:?usage: post_verdict.sh <case-id> < verdict.md}
jq -Rs '{message: .}' | curl -sf -X POST "$THEHIVE_URL/api/v1/case/$CASE_ID/comment" \
  -H "Authorization: Bearer $THEHIVE_APIKEY" -H 'Content-Type: application/json' -d @- | jq '{_id, createdAt}'
