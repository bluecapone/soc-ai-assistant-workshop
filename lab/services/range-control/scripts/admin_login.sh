#!/usr/bin/env bash
# Benign twin of brute_force (rule 100121): a real admin fat-fingers the password a couple of times,
# then succeeds. Same auth-failure shape as the credential spray, but from the IT workstation inside
# the perimeter (workstation-it-01) — an internal, expected source, not the attacker's external IP.
# The wrong guesses, their count and the user-agent vary per run; the final correct password is fixed.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ua="$(pick 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/17.5' 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0' 'Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0')"
echo "admin login from ${ADMIN_IP} (workstation-it-01)"
wrong=(S0cAdmin 'S0cAdmin!' S0cadmin2026 's0cadmin!2026' 'SocAdmin!2026' 'S0cAdmin2026')
nf="$(rint 1 3)"
for ((i=1; i<=nf; i++)); do
  hit POST "/login" "$ADMIN_IP" "$ua" --data-urlencode "username=admin" --data-urlencode "password=$(pick "${wrong[@]}")"
done
# Correct on the final try.
hit POST "/login" "$ADMIN_IP" "$ua" --data-urlencode "username=admin" --data-urlencode "password=S0cAdmin!2026"
