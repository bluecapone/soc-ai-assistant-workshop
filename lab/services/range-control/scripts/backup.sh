#!/usr/bin/env bash
# Benign twin of exfil (rule 100143): the nightly backup job ships the web host's data to the
# internal backup server. Same large-transfer shape as exfil, but the destination is an
# internal/private host (backup-storage) and the agent is a named backup tool (Veeam) — so it is
# authorised. Job, agent version and size vary per run; source and destination stay fixed.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
agent="$(pick 'Veeam Backup/12.1' 'Veeam Backup/12.0' 'Veeam-Agent/6.1' 'Veeam Backup/11.0')"
job="$(pick nightly-db weekly-full db-snapshot config-backup app-data)"
# The job ships a few volumes to the internal backup server — same chunked, large-transfer shape as
# exfil, but the destination is internal and the agent is a named backup tool, so it is authorised.
n="$(rint 2 4)"
echo "backup job (${job}) from ${WEBAPP_IP} -> backup-storage (${BACKUP_IP}) in ${n} volumes"
for ((i=1; i<=n; i++)); do
  xfer_line "$WEBAPP_IP" "$BACKUP_IP" "backup-storage" "$(rand_xfer_bytes)" "$agent"
done
