# Shared helpers for the range-control attack/benign scripts.
# Sourced, not executed.

TARGET="${TARGET_BASE_URL:-http://bank-web:8080}"

# Attacker source IP. The console pins one flagged IP via ATTACKER_IP so every attack
# comes from the address shown to the student (and AbuseIPDB confirms it malicious). If
# unset, fall back to a random flagged IP from the list, then to a random public IP.
MALICIOUS_FILE="${MALICIOUS_IPS_FILE:-/app/threat-intel/malicious-ips.txt}"
rand_attacker_ip() {
  if [ -n "${ATTACKER_IP:-}" ]; then echo "$ATTACKER_IP"; return; fi
  local ip="" lines=() l
  if [ -s "$MALICIOUS_FILE" ]; then
    while IFS= read -r l; do
      case "$l" in ''|\#*) ;; *) lines+=("${l%%[[:space:]]*}") ;; esac
    done < "$MALICIOUS_FILE"
    if [ "${#lines[@]}" -gt 0 ]; then
      ip="${lines[$((RANDOM % ${#lines[@]}))]}"
    fi
  fi
  if [ -z "$ip" ]; then
    ip="$(( (RANDOM % 94) + 100 )).$(( RANDOM % 256 )).$(( RANDOM % 256 )).$(( (RANDOM % 254) + 1 ))"
  fi
  echo "$ip"
}

# A random flagged IP from the malicious list, used as an exfil/C2 *destination* (a live
# AbuseIPDB lookup confirms it is bad) — distinct from the pinned attacker source IP.
rand_malicious_ip() {
  local lines=() l
  if [ -s "$MALICIOUS_FILE" ]; then
    while IFS= read -r l; do
      case "$l" in ''|\#*) ;; *) lines+=("${l%%[[:space:]]*}") ;; esac
    done < "$MALICIOUS_FILE"
  fi
  if [ "${#lines[@]}" -gt 0 ]; then echo "${lines[$((RANDOM % ${#lines[@]}))]}"; else echo "185.220.101.44"; fi
}

# External benign twins (a crawler, a newsletter sender) come from the one clean public IP
# shown on the console (clean on AbuseIPDB). Internal benign activity — an admin logging in,
# a marketing tool calling a CDN — comes from named internal hosts on the network map instead,
# which is what makes it read as legitimate: the source is inside the perimeter, not a stranger.
BENIGN_IP="${BENIGN_IP:-203.0.113.10}"
BENIGN_SCANNER_IP="$BENIGN_IP"
CRAWLER_IP="$BENIGN_IP"

# The IT workstation an engineer/admin actually works from (workstation-it-01 on the map).
# Admin logins to the web app and to SSH originate here, so a reputation/context lookup sees
# an internal, expected source rather than an outside address. The web login is stamped with
# the IP (X-Forwarded-For); the SSH login shows the resolved hostname, the way sshd logs an
# internal source with UseDNS on (the external attacker has no such reverse record).
IT_WORKSTATION_IP="${IT_WORKSTATION_IP:-10.20.20.41}"
IT_WORKSTATION_HOST="${IT_WORKSTATION_HOST:-workstation-it-01}"
ADMIN_IP="$IT_WORKSTATION_IP"
# A marketing/analytics host egressing to a CDN through the proxy (internal source, like any
# other outbound browsing). Distinct from the compromised web host that beacons to C2.
MARKETING_IP="${MARKETING_IP:-10.20.20.51}"
CDN_IP="$MARKETING_IP"

# --- Randomizers: vary IOCs so no two fired alerts look identical -------------
# bash 5 reseeds $RANDOM per subshell, so command-substitution use is safe here.
pick() { local -a a=("$@"); echo "${a[RANDOM % ${#a[@]}]}"; }   # random element of args
rtok() { printf '%04X%04X' "$RANDOM" "$RANDOM"; }               # short hex token, e.g. 1A2B3C4D
rint() { echo $(( (RANDOM % ($2 - $1 + 1)) + $1 )); }           # random int in [$1,$2]

IOCS_FILE="${IOCS_FILE:-/app/threat-intel/iocs.csv}"

# pick_ioc ROLE TYPE  -> prints "value|label|source" for a random matching row (empty if none).
# Labels and sources carry no commas (fetch_threat_intel.py strips them), so a plain , split is safe.
pick_ioc() {
  local role="$1" typ="$2" rows=() line
  if [ -s "$IOCS_FILE" ]; then
    while IFS= read -r line; do rows+=("$line"); done < <(
      awk -F, -v r="$role" -v t="$typ" 'NR>1 && $3==r && $1==t {print $2"|"$4"|"$5}' "$IOCS_FILE")
  fi
  [ "${#rows[@]}" -gt 0 ] && echo "${rows[$((RANDOM % ${#rows[@]}))]}"
}

# Shared pool of realistic staff mailboxes (the mail target is a bank employee).
MAIL_DOMAIN="bankofwonderland.example"
MAIL_RECIPIENTS=(sarah.mitchell james.okonkwo priya.nair david.chen laura.gomez
                 marco.rossi aisha.khan thomas.mueller yuki.tanaka olivia.brown
                 daniel.silva emma.johansson raj.patel sofia.martinez liam.oconnor
                 nadia.hassan kevin.walsh mei.lin arjun.reddy hannah.schmidt)

# hit METHOD PATH SRC_IP USER_AGENT [curl args...]
hit() {
  local method="$1" path="$2" ip="$3" ua="$4"; shift 4
  curl -s -o /dev/null -w "  %{http_code} ${method} ${path}\n" \
    -X "$method" \
    -H "X-Forwarded-For: ${ip}" \
    -H "User-Agent: ${ua}" \
    "$@" \
    "${TARGET}${path}"
}

# --- Authored host logs (SSH auth.log, mail gateway) ------------------------
# SSH and SMTP are not HTTP, so we cannot stamp the source via X-Forwarded-For the way
# the web attacks do. Instead the console writes the log lines itself, with the pinned
# attacker/benign IPs, into a volume Wazuh tails — same detection path, controllable IPs.
HOSTLOG_DIR="${HOSTLOG_DIR:-/var/log/host}"
SSH_LOG="${SSH_LOG:-${HOSTLOG_DIR}/auth.log}"
MAIL_LOG="${MAIL_LOG:-${HOSTLOG_DIR}/maillog}"
SSH_HOST="${SSH_HOST:-web-prod-01}"
MAIL_HOST="${MAIL_HOST:-mail-gateway-01}"

syslog_ts() { date "+%b %e %H:%M:%S"; }   # e.g. "Sep 13 18:30:00"

# ssh_line RESULT USER SRC   (RESULT = Failed | Accepted; SRC = source IP or resolved hostname)
ssh_line() {
  local result="$1" user="$2" ip="$3"
  local pid=$(( (RANDOM % 9000) + 1000 )) port=$(( (RANDOM % 30000) + 20000 ))
  mkdir -p "$HOSTLOG_DIR" 2>/dev/null
  printf '%s %s sshd[%s]: %s password for %s from %s port %s ssh2\n' \
    "$(syslog_ts)" "$SSH_HOST" "$pid" "$result" "$user" "$ip" "$port" >> "$SSH_LOG"
  echo "  auth.log  ${result} password for ${user} from ${ip}"
}

# mail_line VERDICT SENDER SRCIP RECIPIENT URL SUBJECT ATTACHMENT SHA256
mail_line() {
  local verdict="$1" from="$2" ip="$3" to="$4" url="$5" subj="$6" att="${7:-none}" sha="${8:-none}"
  local pid=$(( (RANDOM % 9000) + 1000 ))
  mkdir -p "$HOSTLOG_DIR" 2>/dev/null
  printf '%s %s mailscan[%s]: from=%s ip=%s to=%s verdict=%s url=%s attachment=%s sha256=%s subject="%s"\n' \
    "$(syslog_ts)" "$MAIL_HOST" "$pid" "$from" "$ip" "$to" "$verdict" "$url" "$att" "$sha" "$subj" >> "$MAIL_LOG"
  echo "  maillog   ${verdict} mail to ${to} from ${from} (${ip}) attachment=${att} sha256=${sha}"
}

# --- Data-transfer log (host-to-host transfers: nightly backup, or data exfiltration) -------
# A backup/exfil is not an HTTP request to the web app, it is an egress transfer from the host.
# The console authors it here with fixed internal IPs; the destination + agent are the tells.
XFER_LOG="${XFER_LOG:-${HOSTLOG_DIR}/dataxfer.log}"
XFER_HOST="${XFER_HOST:-web-prod-01}"
WEBAPP_IP="${WEBAPP_IP:-10.20.0.10}"   # web-prod-01's internal address (transfer source)
BACKUP_IP="${BACKUP_IP:-10.20.10.40}"   # internal backup-storage server (authorised destination)

# xfer_line SRC DST DST_HOST BYTES AGENT
xfer_line() {
  local src="$1" dst="$2" dsthost="$3" bytes="$4" agent="$5"
  local pid=$(( (RANDOM % 9000) + 1000 ))
  mkdir -p "$HOSTLOG_DIR" 2>/dev/null
  printf '%s %s dataxfer[%s]: src=%s dst=%s dst_host=%s bytes=%s agent="%s" status=completed\n' \
    "$(syslog_ts)" "$XFER_HOST" "$pid" "$src" "$dst" "$dsthost" "$bytes" "$agent" >> "$XFER_LOG"
  echo "  dataxfer  ${bytes} bytes ${src} -> ${dsthost} (${dst}) via ${agent}"
}

# random transfer size ~0.5-8 GB (always well over the 100 MB volume threshold)
rand_xfer_bytes() { echo $(( ( (RANDOM % 8000) + 500) * 1048576 )); }

# --- Proxy egress log (C2 beacon / CDN callout) -------------------------------------
# The console authors outbound proxy lines into proxy.log. Wazuh tails it; rule 100140 fires on an
# uncategorised outbound egress (the C2 beacon), rule 100141 on an allow-listed CDN callout (twin).
PROXY_LOG="${PROXY_LOG:-${HOSTLOG_DIR}/proxy.log}"
PROXY_HOST="${PROXY_HOST:-proxy-01}"
# Real CDN domains a corporate proxy would allow-list (used by the benign CDN twin).
CDN_ALLOWLIST=(cloudflare.com akamai.net fastly.net edgekey.net cloudfront.net azureedge.net)

# proxy_line SRC DST DST_HOST PORT BYTES UA CAT [TS]
proxy_line() {
  local src="$1" dst="$2" dsthost="$3" port="$4" bytes="$5" ua="$6" cat="$7" ts="${8:-$(syslog_ts)}"
  local pid=$(( (RANDOM % 9000) + 1000 ))
  mkdir -p "$HOSTLOG_DIR" 2>/dev/null
  printf '%s %s proxy[%s]: src=%s dst=%s dst_host=%s port=%s method=CONNECT bytes=%s ua="%s" cat=%s action=allowed\n' \
    "$ts" "$PROXY_HOST" "$pid" "$src" "$dst" "$dsthost" "$port" "$bytes" "$ua" "$cat" >> "$PROXY_LOG"
  echo "  proxy     ${src} -> ${dsthost} (${dst}:${port}) ${bytes}B cat=${cat}"
}
