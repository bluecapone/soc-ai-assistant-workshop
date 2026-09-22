<#
  Bring the whole SOC lab up from nothing and provision every one-time step
  (Windows/PowerShell version of start.sh). Runs from a normal PowerShell prompt;
  no WSL or bash needed. Works on Windows PowerShell 5.1 and PowerShell 7.

    .\clean.ps1 ; .\start.ps1

  Uses curl (curl.exe ships with Windows 10/11) for HTTP, which handles TheHive's
  responses and cookies reliably where Invoke-RestMethod does not.
#>
# Work from the lab root (the dir with docker-compose.yml). This script lives in
# lab/scripts/windows/, so climb up until the compose file is found.
Set-Location $PSScriptRoot
for ($i = 0; $i -lt 3 -and -not (Test-Path docker-compose.yml); $i++) { Set-Location .. }
$ErrorActionPreference = 'Continue'
$env:DOCKER_CLI_HINTS = 'false'   # no "What's next: Debug with Gordon" noise after compose commands

$TH  = "http://localhost:9000"
$N8N = "http://localhost:5678"
$IDX = "https://localhost:9200"

# Lab demo credentials
$THAdmin  = "admin@thehive.local"; $THpw = "brucon2026"
$Analyst  = "analyst@brucon.local"
$N8NOwner = "admin@brucon.local";  $N8Npw = "Brucon2026"

# curl on non-Windows PowerShell (testing), curl.exe on Windows
$curl = if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { 'curl' } else { 'curl.exe' }
$CJ   = (New-TemporaryFile).FullName   # TheHive session cookie jar

function Say($m){ Write-Host "`n== $m ==" -ForegroundColor Cyan }
function Ok($m){  Write-Host "   $m" -ForegroundColor Green }
function Die($m){ Write-Host "   $m" -ForegroundColor Red; exit 1 }

function BodyFile($obj){
    $tmp = (New-TemporaryFile).FullName
    ($obj | ConvertTo-Json -Compress) | Set-Content -Path $tmp -NoNewline -Encoding ascii
    return $tmp
}
function HttpCode($url, [string[]]$extra){
    # Route the body to a temp file, not $null: PowerShell drops $null native args,
    # which would corrupt the curl command line.
    $tmp = (New-TemporaryFile).FullName
    $c = & $curl -s -o $tmp -w '%{http_code}' --max-time 8 @extra $url 2>$null
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    return $c
}
function Wait-Up($url, [string[]]$codes, $label, [string[]]$extra = @()){
    for ($i = 0; $i -lt 60; $i++) {
        $c = HttpCode $url $extra
        if ($codes -contains $c) { Ok "$label up (HTTP $c)"; return }
        Start-Sleep 4
    }
    Die "$label did not come up (last HTTP $c)"
}
function PostJson($url, $obj, [string[]]$extra = @()){
    $bf = BodyFile $obj
    $out = & $curl -s -X POST -H 'Content-Type: application/json' --data "@$bf" @extra $url 2>$null
    Remove-Item $bf -Force -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($out)) { return $null }
    try { return ($out | ConvertFrom-Json) }
    catch { return $null }
}

# --- 0. preflight -------------------------------------------------------------
Say "Preflight"
# Docker must exist and be running first. On Windows we can install Docker Desktop via winget;
# it needs the WSL2 backend and a reboot, so that path installs then asks for a re-run.
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Say "Docker not found - installing Docker Desktop (winget)"
        winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
        Die "Docker Desktop installed. Reboot, launch Docker Desktop (enable the WSL2 backend), then re-run this script."
    } else {
        Die "Docker not found and winget is unavailable. Install Docker Desktop (https://docs.docker.com/desktop/windows/) and re-run."
    }
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Die "Docker is installed but not running - start Docker Desktop (WSL2 backend) and re-run." }
Ok "Docker present and running"
if (-not (Test-Path .env)) { Copy-Item .env.example .env; Ok ".env created from .env.example" }
if (Test-Path .env) { attrib -R .env }   # a leftover/deployed .env may be read-only; the n8n key write-back needs it writable
# Wazuh publishes no arm64 image. On an arm64 host layer docker-compose.amd64.yml,
# which pins only the Wazuh services to linux/amd64. Set it in .env, which compose
# reads, so every later compose command uses the same files.
$envLines = @(Get-Content .env | Where-Object { $_ -notmatch '^COMPOSE_FILE=' })
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($arch -match 'Arm64') { $envLines += 'COMPOSE_FILE=docker-compose.yml;docker-compose.amd64.yml'; Ok "arm64 host: Wazuh services run as linux/amd64 (COMPOSE_FILE in .env)" }
else { Ok "$arch host: native images" }
Set-Content -Path .env -Value ($envLines -join "`n") -NoNewline
try { docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144 | Out-Null; Ok "vm.max_map_count set" }
catch { Ok "vm.max_map_count: skipped (set it in the Docker VM if the indexer fails)" }
Copy-Item -Force platform/wazuh/ossec.conf platform/wazuh/ossec.runtime.conf
Ok "runtime ossec.conf created from template"

# --- 1. up --------------------------------------------------------------------
Say "Starting the stack"
# Docker Desktop auto-creates a missing per-file bind-mount source (each cert *.pem) as an
# empty DIRECTORY when it creates a container, so a plain `up` builds the indexer's cert
# mounts as directories before the generator can write the files, and the indexer crashes
# with "Is a directory". Two defences: if an earlier run already wedged the dir, bring the
# stack down (to release the mounts) and delete the whole generated dir; then generate the
# certs in their own step so every cert exists as a FILE before the indexer/manager/dashboard
# containers are created.
$certDir = "platform/wazuh/certs/generated"
if ((Test-Path $certDir) -and (Get-ChildItem $certDir -Filter *.pem -Directory -ErrorAction SilentlyContinue)) {
    docker compose down --remove-orphans | Out-Null
    Remove-Item -Recurse -Force $certDir
    Ok "cleared a wedged certs dir"
}
docker compose up -d wazuh-certs-generator
$wait = 60
while ($wait -gt 0 -and -not (Test-Path "$certDir/root-ca.pem" -PathType Leaf)) { Start-Sleep -Seconds 2; $wait -= 2 }
docker compose up -d --build

# --- 2. TheHive: password, org, users -----------------------------------------
Say "Provisioning TheHive"
Wait-Up "$TH/api/v1/status" @('200', '401') "TheHive"
# fresh instance is 'secret'; a re-run is already brucon2026
$bf = BodyFile @{ user = $THAdmin; password = 'secret' }
$dump = (New-TemporaryFile).FullName
$code = & $curl -s -o $dump -w '%{http_code}' -c $CJ -X POST -H 'Content-Type: application/json' --data "@$bf" "$TH/api/v1/login" 2>$null
Remove-Item $bf, $dump -Force -ErrorAction SilentlyContinue
if ($code -eq '200') {
    PostJson "$TH/api/v1/user/$THAdmin/password/set" @{ password = $THpw } @('-b', $CJ) | Out-Null
    Ok "admin password set to $THpw"
}
PostJson "$TH/api/v1/login" @{ user = $THAdmin; password = $THpw } @('-c', $CJ) | Out-Null

# Create organisation if it doesn't exist
$OrgCheck = & $curl -s -w '%{http_code}' -o $null -b $CJ -X GET "$TH/api/v1/organisation/soclab" 2>$null
if ($OrgCheck -match '200') {
    Ok "org soclab already exists"
} else {
    PostJson "$TH/api/v1/organisation" @{ name = "soclab"; description = "workshop" } @('-b', $CJ) | Out-Null
    Ok "org soclab created"
}

# A machine account must be a TheHive "service" user (unlimited by the licence). If a
# stack provisioned before that rule still carries it as a normal user, delete it
# permanently (TheHive's plain DELETE only locks) so the create below can set the type.
function FixUserType($login) {
    $q = PostJson "$TH/api/v1/query" @{ query = @( @{ _name = "listUser" }, @{ _name = "filter"; _and = @( @{ _field = "login"; _value = $login } ) } ) } @('-b', $CJ)
    if ($q -and $q[0]._id -and $q[0].type -ne 'Service') {
        & $curl -s -o "$env:TEMP\fixuser-null" -b $CJ -X DELETE "$TH/api/v1/user/$($q[0]._id)/force" 2>$null
        Ok "$login was a $($q[0].type) user; removed so it can be recreated as a service user"
    }
}
FixUserType integrator@soclab.local
# Delete and recreate integrator user to ensure correct profile
& $curl -s -X DELETE -b $CJ "$TH/api/v1/user/integrator@soclab.local" 2>$null | Out-Null
# type=service: machine accounts (integrator, n8n) use the unlimited users.service license
# quota, not users.normal (capped at 2 on the trial license). Only the human analyst is normal.
PostJson "$TH/api/v1/user" @{ login = "integrator@soclab.local"; name = "Wazuh Integrator"; organisation = "soclab"; profile = "analyst"; type = "service" } @('-b', $CJ) | Out-Null
Ok "integrator ready"

# Ensure integrator is unlocked
$IUserQuery = PostJson "$TH/api/v1/query" @{ query = @( @{ _name = "listUser" }, @{ _name = "filter"; _and = @( @{ _field = "login"; _value = "integrator@soclab.local" } ) } ) } @('-b', $CJ)
if ($IUserQuery -and $IUserQuery[0]._id) {
  PostJson "$TH/api/v1/user/$($IUserQuery[0]._id)" @{ locked = $false } @('-b', $CJ, '-X', 'PATCH') | Out-Null
}

# Delete and recreate analyst user to ensure correct profile
& $curl -s -X DELETE -b $CJ "$TH/api/v1/user/$Analyst" 2>$null | Out-Null
PostJson "$TH/api/v1/user" @{ login = $Analyst; name = "SOC Analyst"; organisation = "soclab"; profile = "analyst" } @('-b', $CJ) | Out-Null
PostJson "$TH/api/v1/user/$Analyst/password/set" @{ password = $THpw } @('-b', $CJ) | Out-Null
Ok "analyst $Analyst ready"

# Ensure analyst is unlocked
$AUserQuery = PostJson "$TH/api/v1/query" @{ query = @( @{ _name = "listUser" }, @{ _name = "filter"; _and = @( @{ _field = "login"; _value = $Analyst } ) } ) } @('-b', $CJ)
if ($AUserQuery -and $AUserQuery[0]._id) {
  PostJson "$TH/api/v1/user/$($AUserQuery[0]._id)" @{ locked = $false } @('-b', $CJ, '-X', 'PATCH') | Out-Null
}
$IKEY = (& $curl -s -X POST -b $CJ "$TH/api/v1/user/integrator@soclab.local/key/renew" 2>$null).Trim()
if ($IKEY -match '^\{' -or $IKEY.Length -lt 16) { Die "could not mint integrator key: $IKEY" }
Ok "integrator API key minted"

# --- 3. wire the Wazuh -> TheHive integrator ----------------------------------
Say "Wiring the Wazuh integrator"
# Regenerate the runtime config from the template with the real TheHive URL + integrator key.
# Read the template (ossec.conf) and write runtime.conf in place with Set-Content, which
# truncates the existing file rather than recreating it. The running manager bind-mounts this
# exact file (./ossec.runtime.conf -> /wazuh-config-mount/etc/ossec.conf); replacing the file
# instead of truncating it in place would detach the single-file mount and make the exec cp
# below fail with "No such file or directory".
$conf = (Get-Content platform/wazuh/ossec.conf -Raw).Replace('WORKSHOP_THEHIVE_URL', 'http://thehive:9000').Replace('WORKSHOP_THEHIVE_APIKEY', $IKEY)
Set-Content -Path platform/wazuh/ossec.runtime.conf -Value $conf -NoNewline
# Copy the workshop config in with docker compose cp, which does not go through the
# /wazuh-config-mount bind mount (seen missing inside the container right after a
# recreate on Docker Desktop). The mount stays for the image's own init script.
function CopyIn($src, $dst) {
    docker compose cp $src "wazuh.manager:$dst" *> $null
    if ($LASTEXITCODE -ne 0) { Die "could not copy $src into wazuh.manager; re-run .\start.ps1" }
}
CopyIn platform/wazuh/ossec.runtime.conf /var/ossec/etc/ossec.conf
CopyIn platform/wazuh/local_rules.xml    /var/ossec/etc/rules/local_rules.xml
CopyIn platform/wazuh/local_decoder.xml  /var/ossec/etc/decoders/local_decoder.xml
foreach ($f in 'custom-w2thive', 'custom-w2thive.py', 'custom-n8n', 'custom-n8n.py') { CopyIn "platform/wazuh/integrations/$f" "/var/ossec/integrations/$f" }
docker compose exec -T wazuh.manager chmod +x /var/ossec/integrations/custom-w2thive /var/ossec/integrations/custom-w2thive.py /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
Ok "workshop config copied into wazuh.manager"
docker compose restart wazuh.manager | Out-Null
for ($i = 0; $i -lt 30; $i++) {
    docker compose exec -T wazuh.manager sh -c '/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-logcollector is running"' 2>$null
    if ($LASTEXITCODE -eq 0) { Ok "manager restarted, logcollector running"; break }
    Start-Sleep 4
}

# --- 4. n8n: owner + workflow -------------------------------------------------
Say "Provisioning n8n"
Wait-Up "$N8N/healthz" @('200') "n8n"
PostJson "$N8N/rest/owner/setup" @{ email = $N8NOwner; firstName = "BruCon"; lastName = "Admin"; password = $N8Npw } | Out-Null
Ok "owner $N8NOwner set (wizard skipped)"
# Re-establish the admin session before provisioning the n8n user: the Wazuh restart + wait
# above can outlast TheHive's session, which would make the create below fail and the later
# key/renew 404 with "User not found".
PostJson "$TH/api/v1/login" @{ user = $THAdmin; password = $THpw } @('-c', $CJ) | Out-Null
FixUserType n8n@soclab.local
# Delete and recreate n8n user to ensure correct profile
& $curl -s -X DELETE -b $CJ "$TH/api/v1/user/n8n@soclab.local" 2>$null | Out-Null
PostJson "$TH/api/v1/user" @{ login = "n8n@soclab.local"; name = "n8n verdict writer"; organisation = "soclab"; profile = "analyst"; type = "service" } @('-b', $CJ) | Out-Null
Ok "n8n user ready"

# Ensure n8n is unlocked
$NUserQuery = PostJson "$TH/api/v1/query" @{ query = @( @{ _name = "listUser" }, @{ _name = "filter"; _and = @( @{ _field = "login"; _value = "n8n@soclab.local" } ) } ) } @('-b', $CJ)
if ($NUserQuery -and $NUserQuery[0]._id) {
  PostJson "$TH/api/v1/user/$($NUserQuery[0]._id)" @{ locked = $false } @('-b', $CJ, '-X', 'PATCH') | Out-Null
}

# Mint the n8n writer key
$NKEY = (& $curl -s -X POST -b $CJ "$TH/api/v1/user/n8n@soclab.local/key/renew" 2>$null).Trim()
if ($NKEY -match '^\{' -or $NKEY.Length -lt 16) { Die "could not mint n8n key: $NKEY" }
Ok "n8n writer API key minted"

# Fix .env with the newly minted n8n key
$env_content = Get-Content .env -Raw
$env_content = $env_content -replace 'THEHIVE_N8N_APIKEY=.*', "THEHIVE_N8N_APIKEY=$NKEY"
Set-Content -Path .env -Value $env_content -NoNewline

# Helper to get env values
function Get-EnvValue($key) {
    (Select-String "^$key=" .env | Select-Object -First 1).Line -replace "^$key=" | Write-Output
}
$GW_URL = Get-EnvValue "GATEWAY_BASE_URL"
$GW_KEY = Get-EnvValue "GATEWAY_API_KEY"

# Credential ids are fixed; the checkpoint workflows reference them by id
$CREDS = @"
[{"id":"credWazuhIndex01","name":"Wazuh indexer","type":"httpBasicAuth","data":{"user":"admin","password":"$THpw"}},
 {"id":"credTheHiveN8n01","name":"TheHive n8n","type":"httpHeaderAuth","data":{"name":"Authorization","value":"Bearer $NKEY"}},
 {"id":"credModelGatewy1","name":"Model gateway","type":"openAiApi","data":{"apiKey":"$GW_KEY","url":"$GW_URL"}}]
"@

$CREDS | docker compose exec -T n8n sh -c 'cat > /tmp/creds.json && n8n import:credentials --input=/tmp/creds.json >/dev/null 2>&1; rc=$?; rm -f /tmp/creds.json; exit $rc' | Out-Null
if ($LASTEXITCODE -eq 0) {
    Ok "n8n credentials provisioned (Wazuh indexer, TheHive n8n, Model gateway)"
} else {
    Die "n8n credential import failed"
}

# Workflow importer
function Import-Workflow($workflow_id, $path, $label) {
    $list_out = docker compose exec -T n8n n8n list:workflow 2>$null
    if ($list_out | Select-String -Pattern $workflow_id -Quiet) {
        Ok "$label already present"
    } else {
        docker compose exec -T n8n n8n import:workflow --input=$path > $null 2>&1
        if ($LASTEXITCODE -eq 0) { Ok "$label imported" } else { Die "$label import failed" }
    }
}
Import-Workflow "soctriageskel001" "/import-exercises/module-2/skeleton.json"          "Module 2 skeleton"
Import-Workflow "soctriagem2chk01" "/import-checkpoints/module-2/triage-m2-chain.json" "Module 2 checkpoint"
Import-Workflow "soctriagem3chk01" "/import-checkpoints/module-3/triage-m3-agent.json" "Module 3 checkpoint"


# --- 5. Wazuh reachable -------------------------------------------------------
Say "Checking Wazuh"
Wait-Up "$IDX/_cluster/health" @('200') "Wazuh indexer" @('-k', '-u', "admin:$THpw")

Remove-Item $CJ -Force -ErrorAction SilentlyContinue

# --- summary ------------------------------------------------------------------
Say "Ready"
@"
   Attack console   http://panel.localhost    (or :8000)   no login
   Bank website     http://web.localhost      (or :8080)   no login
   TheHive          http://thehive.localhost  (or :9000)   $Analyst / $THpw
   Wazuh SIEM       http://wazuh.localhost     (or :8443)   admin / $THpw
   n8n              http://n8n.localhost       (or :5678)   $N8NOwner / $N8Npw
   TheHive API key  THEHIVE_N8N_APIKEY in .env (Module 1 skill and n8n write-back)

   Fire a button on the attack console and watch the case land in TheHive.
   Service logins are also on the attack console sidebar (click any to copy).
"@ | Write-Host
