#!/usr/bin/env bash
# Benign twin of recon noise (rule 100151): a legitimate high-volume crawler. High request
# count, real search-engine user-agent, valid paths, no 404 storm. The bot, the query terms
# and the request count vary per run (always >=12 events so the frequency rule still fires).
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ua="$(pick 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' 'Mozilla/5.0 (compatible; DuckDuckBot-crawler/1.1; +https://duckduckgo.com/duckduckbot)')"
terms=(widget gadget invoice pricing support login account careers blog api docs mortgage savings loans)
n="$(rint 25 40)"
echo "heavy crawler from ${CRAWLER_IP} (${n} pages, UA=${ua})"
for ((i=1; i<=n; i++)); do
  hit GET "/search?q=$(pick "${terms[@]}")" "$CRAWLER_IP" "$ua"
  hit GET "/" "$CRAWLER_IP" "$ua"
done
