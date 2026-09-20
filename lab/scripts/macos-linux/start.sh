#!/usr/bin/env bash
# Bring the whole SOC lab up from nothing and provision every one-time step, so a
# fresh stack is fully working: TheHive password + org + users + integrator key, the
# Wazuh->TheHive wiring, and the n8n owner + workflow. Safe to re-run.
#
#   ./clean.sh && ./start.sh
#
# Slow the first time (containers pull + JVMs boot, slower still under emulation).
set -uo pipefail
export DOCKER_CLI_HINTS=false   # no "What's next: Debug with Gordon" noise after compose commands
# Work from the lab root (the dir with docker-compose.yml). This script lives in
# lab/scripts/macos-linux/, so climb up until the compose file is found.
cd "$(dirname "$0")"
for _ in 1 2 3; do [ -f docker-compose.yml ] && break; cd ..; done

TH="http://localhost:9000"
N8N="http://localhost:5678"
IDX="https://localhost:9200"
COOKIE="$(mktemp)"
say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()  { printf '   \033[32m%s\033[0m\n' "$*"; }
die() { printf '   \033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# --- credentials (the lab demo creds) ----------------------------------------
TH_ADMIN="admin@thehive.local"; TH_PW="brucon2026"
ANALYST="analyst@brucon.local"
N8N_OWNER="admin@brucon.local"; N8N_PW="Brucon2026"

wait_code() {  # wait_code <url> <curl-opts> <regex-of-acceptable-codes> <label>
  local url="$1" opts="$2" want="$3" label="$4" code
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' $opts "$url" 2>/dev/null || echo 000)"
    [[ "$code" =~ $want ]] && { ok "$label up (HTTP $code)"; return 0; }
    sleep 4
  done
  die "$label did not come up (last HTTP $code)"
}

# --- 0. prep ------------------------------------------------------------------
say "Preflight"
# Docker must exist and be running before anything else. On Linux we can install it
# unattended; Docker Desktop on macOS/Windows is a GUI install we can only point to.
if ! command -v docker >/dev/null 2>&1; then
  case "$(uname -s)" in
    Linux)  say "Docker not found — installing (Linux)"
            curl -fsSL https://get.docker.com | sh || die "Docker install failed; install it manually and re-run"
            ok "Docker installed (you may need to log out/in for group changes)" ;;
    *)      die "Docker not found. Install Docker Desktop (https://docs.docker.com/desktop/), start it, then re-run." ;;
  esac
fi
docker info >/dev/null 2>&1 || die "Docker is installed but the daemon isn't running — start Docker Desktop / the docker service and re-run."
ok "Docker present and running"
[ -f .env ] || { cp .env.example .env; ok ".env created from .env.example"; }
# Wazuh publishes no arm64 image. On an arm64 host (Apple Silicon, Graviton) layer
# docker-compose.amd64.yml, which pins only the Wazuh services to linux/amd64. Set it
# in .env, which compose reads, so every later compose command (this script, clean.sh,
# an attendee's docker compose logs) uses the same files and never recreates a service.
sed -i.bak '/^COMPOSE_FILE=/d' .env && rm -f .env.bak
case "$(uname -m)" in
  arm64|aarch64) echo 'COMPOSE_FILE=docker-compose.yml:docker-compose.amd64.yml' >> .env; ok "arm64 host: Wazuh services run as linux/amd64 (COMPOSE_FILE in .env)" ;;
  *)             ok "$(uname -m) host: native images" ;;
esac
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 \
  && ok "vm.max_map_count set" || ok "vm.max_map_count: skipped (set it in the Docker VM if the indexer fails)"
cp -f platform/wazuh/ossec.conf platform/wazuh/ossec.runtime.conf
ok "runtime ossec.conf created from template"

# --- 1. bring everything up ---------------------------------------------------
say "Starting the stack"
# Docker auto-creates a missing per-file bind-mount source (each cert *.pem) as an empty
# DIRECTORY at container-create time, so a plain `up` builds the indexer's cert mounts as
# directories before the generator can write the files -> "Is a directory" crash. Two
# defences: clear a previously-wedged dir (stack down first to release the mounts, then
# delete the whole dir), then generate the certs in their own step so every cert is a FILE
# before the indexer/manager/dashboard containers are created.
certdir="platform/wazuh/certs/generated"
if [ -d "$certdir" ]; then
  for p in "$certdir"/*.pem; do
    [ -d "$p" ] && { docker compose down --remove-orphans >/dev/null 2>&1; rm -rf "$certdir"; ok "cleared a wedged certs dir"; break; }
  done
fi
docker compose up -d wazuh-certs-generator
for _ in $(seq 1 30); do [ -f "$certdir/root-ca.pem" ] && break; sleep 2; done
docker compose up -d --build

# --- 2. TheHive: password, org, users -----------------------------------------
say "Provisioning TheHive"
wait_code "$TH/api/v1/status" "" "^(200|401)$" "TheHive"
# fresh instance is 'secret'; a re-run is already brucon2026
if curl -s -o /dev/null -c "$COOKIE" -X POST "$TH/api/v1/login" -H 'Content-Type: application/json' \
     -d "{\"user\":\"$TH_ADMIN\",\"password\":\"secret\"}" -w '%{http_code}' | grep -q 200; then
  curl -s -o /dev/null -b "$COOKIE" -X POST "$TH/api/v1/user/$TH_ADMIN/password/set" \
    -H 'Content-Type: application/json' -d "{\"password\":\"$TH_PW\"}"
  ok "admin password set to $TH_PW"
fi
curl -s -o /dev/null -c "$COOKIE" -X POST "$TH/api/v1/login" -H 'Content-Type: application/json' \
  -d "{\"user\":\"$TH_ADMIN\",\"password\":\"$TH_PW\"}"
# Create organisation if it doesn't exist
if ! curl -s -o /dev/null -b "$COOKIE" -w '%{http_code}' -X GET "$TH/api/v1/organisation/soclab" | grep -q '^200$'; then
  curl -s -o /dev/null -b "$COOKIE" -X POST "$TH/api/v1/organisation" -H 'Content-Type: application/json' \
    -d '{"name":"soclab","description":"workshop"}'; ok "org soclab created"
else
  ok "org soclab already exists"
fi

# A machine account must be a TheHive "service" user (unlimited by the licence). If a
# stack provisioned before that rule still carries it as a normal user, delete it
# permanently (TheHive's plain DELETE only locks) so the create below can set the type.
fix_user_type() {  # fix_user_type <login>
  local rec id type
  rec="$(curl -s -b "$COOKIE" -X POST "$TH/api/v1/query" -H 'Content-Type: application/json' -d "{\"query\":[{\"_name\":\"listUser\"},{\"_name\":\"filter\",\"_and\":[{\"_field\":\"login\",\"_value\":\"$1\"}]}]}")"
  id="$(jq -r '.[0]._id // empty' <<<"$rec")"; type="$(jq -r '.[0].type // empty' <<<"$rec")"
  if [ -n "$id" ] && [ "$type" != "Service" ]; then
    curl -s -o /dev/null -b "$COOKIE" -X DELETE "$TH/api/v1/user/$id/force" && ok "$1 was a $type user; removed so it can be recreated as a service user"
  fi
}
fix_user_type integrator@soclab.local
# Delete and recreate integrator user to ensure correct profile
curl -s -o /dev/null -b "$COOKIE" -X DELETE "$TH/api/v1/user/integrator@soclab.local"

# type=service: machine accounts (integrator, n8n) use the unlimited users.service license
# quota, not users.normal (capped at 2 on the trial license). Only the human analyst is normal.
curl -s -o /dev/null -b "$COOKIE" -X POST "$TH/api/v1/user" -H 'Content-Type: application/json' \
  -d '{"login":"integrator@soclab.local","name":"Wazuh Integrator","organisation":"soclab","profile":"analyst","type":"service"}'; ok "integrator ready"

# Ensure integrator is unlocked
IUSER_ID="$(curl -s -b "$COOKIE" -X POST "$TH/api/v1/query" -H 'Content-Type: application/json' -d '{"query":[{"_name":"listUser"},{"_name":"filter","_and":[{"_field":"login","_value":"integrator@soclab.local"}]}]}' | jq -r '.[0]._id')"
curl -s -o /dev/null -b "$COOKIE" -X PATCH "$TH/api/v1/user/$IUSER_ID" -H 'Content-Type: application/json' -d '{"locked":false}'

# Delete and recreate analyst user to ensure correct profile
curl -s -o /dev/null -b "$COOKIE" -X DELETE "$TH/api/v1/user/$ANALYST"
curl -s -o /dev/null -b "$COOKIE" -X POST "$TH/api/v1/user" -H 'Content-Type: application/json' \
  -d "{\"login\":\"$ANALYST\",\"name\":\"SOC Analyst\",\"organisation\":\"soclab\",\"profile\":\"analyst\"}"
curl -s -o /dev/null -b "$COOKIE" -X POST "$TH/api/v1/user/$ANALYST/password/set" \
  -H 'Content-Type: application/json' -d "{\"password\":\"$TH_PW\"}"; ok "analyst $ANALYST ready"

# Ensure the analyst is unlocked. TheHive creates the user locked, and a locked user cannot
# authenticate (login returns AuthenticationError), so this step is required, not cosmetic.
# The integrator and n8n users below are unlocked the same way; start.sh had simply omitted it
# for the analyst (start.ps1 already did it).
AUSER_ID="$(curl -s -b "$COOKIE" -X POST "$TH/api/v1/query" -H 'Content-Type: application/json' -d "{\"query\":[{\"_name\":\"listUser\"},{\"_name\":\"filter\",\"_and\":[{\"_field\":\"login\",\"_value\":\"$ANALYST\"}]}]}" | jq -r '.[0]._id')"
curl -s -o /dev/null -b "$COOKIE" -X PATCH "$TH/api/v1/user/$AUSER_ID" -H 'Content-Type: application/json' -d '{"locked":false}'
IKEY="$(curl -s -b "$COOKIE" -X POST "$TH/api/v1/user/integrator@soclab.local/key/renew")"
[[ ! "$IKEY" =~ \{ ]] && [ ${#IKEY} -ge 16 ] && ok "integrator API key minted" || die "could not mint integrator key: $IKEY"
# --- 3. wire the Wazuh -> TheHive integrator ----------------------------------
say "Wiring the Wazuh integrator"
# Regenerate the runtime config from the template with the real TheHive URL + integrator key.
# Write with a truncate-in-place redirect (>), NOT sed -i: sed -i (and mv, and most editors)
# create a new file and rename it over the target, which swaps the inode. The running manager
# bind-mounts this exact file (./ossec.runtime.conf -> /wazuh-config-mount/etc/ossec.conf), and
# a single-file bind mount is tied to the original inode, so swapping it detaches the mount and
# the exec cp below fails with "No such file or directory". Redirecting into the existing file
# keeps its inode, so the mount stays valid and sees the new contents.
sed "s|WORKSHOP_THEHIVE_URL|http://thehive:9000|; s|WORKSHOP_THEHIVE_APIKEY|${IKEY}|" \
  platform/wazuh/ossec.conf > platform/wazuh/ossec.runtime.conf
# Copy the workshop config in with docker compose cp, which does not go through the
# /wazuh-config-mount bind mount: on Docker Desktop that mount has been seen missing
# inside the container right after a (re)create. The mount stays for the image's own
# init script, which reads it at container start.
copy_in() {  # copy_in <host path> <container path>
  docker compose cp "$1" "wazuh.manager:$2" >/dev/null 2>&1 || die "could not copy $1 into wazuh.manager; re-run ./start.sh"
}
copy_in platform/wazuh/ossec.runtime.conf              /var/ossec/etc/ossec.conf
copy_in platform/wazuh/local_rules.xml                 /var/ossec/etc/rules/local_rules.xml
copy_in platform/wazuh/local_decoder.xml               /var/ossec/etc/decoders/local_decoder.xml
for f in custom-w2thive custom-w2thive.py custom-n8n custom-n8n.py; do
  copy_in "platform/wazuh/integrations/$f" "/var/ossec/integrations/$f"
done
docker compose exec -T wazuh.manager chmod +x /var/ossec/integrations/custom-w2thive /var/ossec/integrations/custom-w2thive.py /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
ok "workshop config copied into wazuh.manager"
docker compose restart wazuh.manager >/dev/null
for _ in $(seq 1 30); do
  docker compose exec -T wazuh.manager sh -c '/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-logcollector is running"' \
    && { ok "manager restarted, logcollector running"; break; }
  sleep 4
done

# --- 4. n8n: owner + workflow -------------------------------------------------
say "Provisioning n8n"
wait_code "$N8N/healthz" "" "^200$" "n8n"
curl -s -o /dev/null -X POST "$N8N/rest/owner/setup" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$N8N_OWNER\",\"firstName\":\"BruCon\",\"lastName\":\"Admin\",\"password\":\"$N8N_PW\"}"
ok "owner $N8N_OWNER set (wizard skipped)"
# Re-establish the admin session before provisioning the n8n user. The Wazuh restart + wait
# above can outlast TheHive's session; a stale session makes the create below fail, and because
# the response was discarded the later key/renew 404s with "User not found". Refresh the session,
# then surface the create's HTTP status so any remaining failure is visible instead of masked.
curl -s -o /dev/null -c "$COOKIE" -X POST "$TH/api/v1/login" -H 'Content-Type: application/json' \
  -d "{\"user\":\"$TH_ADMIN\",\"password\":\"$TH_PW\"}"
fix_user_type n8n@soclab.local
# Delete and recreate n8n user to ensure correct profile
curl -s -o /dev/null -b "$COOKIE" -X DELETE "$TH/api/v1/user/n8n@soclab.local"

NCREATE="$(curl -s -o /dev/null -b "$COOKIE" -w '%{http_code}' -X POST "$TH/api/v1/user" -H 'Content-Type: application/json' \
  -d '{"login":"n8n@soclab.local","name":"n8n verdict writer","organisation":"soclab","profile":"analyst","type":"service"}')"
case "$NCREATE" in
  201|400|409) ok "n8n user ready (HTTP $NCREATE)" ;;
  *) printf '   \033[31mn8n user create returned HTTP %s (key mint below will fail if the user was not created)\033[0m\n' "$NCREATE" ;;
esac

# Ensure n8n is unlocked
NUSER_ID="$(curl -s -b "$COOKIE" -X POST "$TH/api/v1/query" -H 'Content-Type: application/json' -d '{"query":[{"_name":"listUser"},{"_name":"filter","_and":[{"_field":"login","_value":"n8n@soclab.local"}]}]}' | jq -r '.[0]._id')"
curl -s -o /dev/null -b "$COOKIE" -X PATCH "$TH/api/v1/user/$NUSER_ID" -H 'Content-Type: application/json' -d '{"locked":false}'

# Mint the n8n writer key
NKEY="$(curl -s -b "$COOKIE" -X POST "$TH/api/v1/user/n8n@soclab.local/key/renew")"
[[ ! "$NKEY" =~ \{ ]] && [ ${#NKEY} -ge 16 ] && ok "n8n writer API key minted" || die "could not mint n8n key: $NKEY"

# Fix .env with the newly minted n8n key
sed -i.bak "s|THEHIVE_N8N_APIKEY=.*|THEHIVE_N8N_APIKEY=${NKEY}|" .env
rm -f .env.bak

# Helper to get env values
envval() { grep "^$1=" .env | head -1 | cut -d= -f2-; }
GW_URL="$(envval GATEWAY_BASE_URL)"; GW_KEY="$(envval GATEWAY_API_KEY)"

# Credential ids are fixed; the checkpoint workflows reference them by id. Import upserts,
# so a re-run refreshes the (rotated) TheHive key in place.
CREDS=$(cat <<CREDSEOF
[{"id":"credWazuhIndex01","name":"Wazuh indexer","type":"httpBasicAuth","data":{"user":"admin","password":"$TH_PW"}},
 {"id":"credTheHiveN8n01","name":"TheHive n8n","type":"httpHeaderAuth","data":{"name":"Authorization","value":"Bearer ${NKEY}"}},
 {"id":"credModelGatewy1","name":"Model gateway","type":"openAiApi","data":{"apiKey":"${GW_KEY}","url":"${GW_URL}"}}]
CREDSEOF
)
printf '%s' "$CREDS" | docker compose exec -T n8n sh -c 'cat > /tmp/creds.json && n8n import:credentials --input=/tmp/creds.json >/dev/null 2>&1; rc=$?; rm -f /tmp/creds.json; exit $rc' \
  && ok "n8n credentials provisioned (Wazuh indexer, TheHive n8n, Model gateway)" || die "n8n credential import failed"

# Workflow importer
import_wf() {  # import_wf <workflow-id> <path-in-container> <label>
  if docker compose exec -T n8n n8n list:workflow 2>/dev/null | grep -q "$1"; then
    ok "$3 already present"
  elif docker compose exec -T n8n n8n import:workflow --input="$2" >/dev/null 2>&1; then
    ok "$3 imported"
  else
    die "$3 import failed"
  fi
}
import_wf soctriageref001  /import/triage-workflow.json                      "reference workflow"
import_wf soctriageskel001 /import-exercises/module-2/skeleton.json          "Module 2 skeleton"
import_wf soctriagem2chk01 /import-checkpoints/module-2/triage-m2-chain.json "Module 2 checkpoint"
import_wf soctriagem3chk01 /import-checkpoints/module-3/triage-m3-agent.json "Module 3 checkpoint"


# --- 5. Wazuh reachable (fresh init applies the internal_users password) -------
say "Checking Wazuh"
wait_code "$IDX/_cluster/health" "-sk -u admin:$TH_PW" "^200$" "Wazuh indexer"

rm -f "$COOKIE"
say "Ready"
cat <<EOF
   Attack console   http://panel.localhost    (or :8000)   no login
   Bank website     http://web.localhost      (or :8080)   no login
   TheHive          http://thehive.localhost  (or :9000)   $ANALYST / $TH_PW
   Wazuh SIEM       http://wazuh.localhost     (or :8443)   admin / $TH_PW
   n8n              http://n8n.localhost       (or :5678)   $N8N_OWNER / $N8N_PW
   TheHive API key  THEHIVE_N8N_APIKEY in .env (Module 1 skill and n8n write-back)

   Fire a button on the attack console and watch the case land in TheHive.
   Service logins are also on the attack console sidebar (click any to copy).
EOF
