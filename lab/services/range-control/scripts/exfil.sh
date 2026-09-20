#!/usr/bin/env bash
# Attack (rule 100142): the compromised web host ships a large volume of data OUT to an external
# destination via a generic grab tool. Same transfer shape as the nightly backup (100143) — the
# tells are the EXTERNAL destination and the grab tool (vs an internal server + Veeam). The
# destination IP, host name, agent and transfer size all vary per run.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
if [ -n "${MALICIOUS_DEST_IP:-}" ]; then
  dst="$MALICIOUS_DEST_IP"; fam="exfil"
else
  IFS='|' read -r dst fam _s <<<"$(pick_ioc exfil ip)"
  : "${dst:=$(rand_malicious_ip)}"
fi
: "${fam:=unknown}"
# Real drop host: a flagged domain from the feed doubles as the exfil destination, so a VirusTotal
# lookup returns a genuine verdict. Falls back to the destination IP as the host, never a fake name.
IFS='|' read -r dsthost _dl _ds <<<"$(pick_ioc c2 domain)"
: "${dsthost:=$dst}"
agent="$(pick curl/8.5.0 python-requests/2.31 Wget/1.21 Go-http-client/1.1)"
# Staged exfil: a few large chunks to the SAME external destination, not one monolithic transfer.
n="$(rint 2 4)"
echo "data exfiltration from ${WEBAPP_IP} -> ${dsthost} (${dst}, ${fam}) in ${n} chunks"
for ((i=1; i<=n; i++)); do
  xfer_line "$WEBAPP_IP" "$dst" "$dsthost" "$(rand_xfer_bytes)" "$agent"
done
