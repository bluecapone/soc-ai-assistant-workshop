#!/bin/sh
# Self-heal the Wazuh manager if wazuh-logcollector dies. Under qemu emulation (an
# Apple-Silicon Mac running the amd64-only Wazuh) logcollector crashes on a select()
# interrupt; when it does, the manager stops reading the target's logs and no cases get
# created. This checks every 30s and restarts the wazuh daemons in place if logcollector
# is gone, so detection resumes on its own — no student action, no Docker settings.
# On native x86 the crash does not happen and this simply never fires.
set -u
M="${MANAGER_CONTAINER:-wazuh.manager}"
echo "[watchdog] watching $M logcollector every 30s"
while true; do
  if docker exec "$M" sh -c '/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-logcollector is running"' 2>/dev/null; then
    :
  else
    echo "[watchdog] $(date -u +%H:%M:%S) logcollector down — restarting wazuh daemons"
    docker exec "$M" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
  fi
  sleep 30
done
