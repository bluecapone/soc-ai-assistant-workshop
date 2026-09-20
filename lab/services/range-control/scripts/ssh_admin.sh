#!/usr/bin/env bash
# Decoy (rule 100161): a routine, clean SSH login for an ops account from the IT workstation inside
# the perimeter. The auth.log line names the source host (workstation-it-01), the way sshd logs an
# internal client it can resolve — so the "from" field reads as a known workstation, not an IP the
# analyst has to look up, and certainly not the attacker's external address. Same event type as the
# SSH compromise, but no brute force preceded it and the source is internal. Deliberately a single
# clean success (no failures) so it never looks like the brute force itself. The account varies.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
user="$(pick deploy ansible ops-admin backup-svc jenkins release)"
echo "Admin SSH login as ${user} from ${IT_WORKSTATION_HOST} (${IT_WORKSTATION_IP})"
ssh_line Accepted "$user" "$IT_WORKSTATION_HOST"
