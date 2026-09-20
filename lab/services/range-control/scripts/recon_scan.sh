#!/usr/bin/env bash
# Attack (rule 100100): reconnaissance of the app's real attack surface, then a wordlist sweep of
# sensitive paths — a directory-buster run, not a couple of pokes. A browser user-agent (no scanner
# giveaway). Rule 100100 fires on the burst of 404s from one source; ignore=60 collapses the burst
# into one case. The real endpoints hit and the probe paths vary per run.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ip="$(rand_attacker_ip)"
ua="$(pick 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36' \
          'Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0')"
# Touch the real endpoints (these 200/302), so it reads as targeted enumeration of THIS app.
for ep in / /login '/search?q=savings' /upload /run /download; do hit GET "$ep" "$ip" "$ua"; done
# A realistic sensitive-path wordlist. Most 404; the burst is what trips the rule.
probes=(/.git/config /.git/HEAD /.env /.env.local /backup.zip /backup.tar.gz /db.sql /dump.sql
        /wp-login.php /wp-admin/ /xmlrpc.php /phpmyadmin /pma /adminer.php /server-status
        /server-info /config.php /config.php.bak /config.yml /settings.py /.htaccess /web.config
        /.svn/entries /.hg/ /.DS_Store /crossdomain.xml /robots.txt /sitemap.xml /admin /admin.php
        /administrator /manager/html /console /actuator /actuator/env /actuator/health /metrics
        /debug /test.php /info.php /phpinfo.php /.aws/credentials /.ssh/id_rsa /id_rsa /vendor/phpunit
        /composer.json /package.json /api /api/v1 /api/v2 /swagger.json /openapi.json /graphql
        /.well-known/security.txt /cgi-bin/ /shell.php /uploads/ /files/ /tmp/ /old/ /new/ /backup/
        /private/ /secret/ /internal/ /staging/ /dev/)
n="$(rint 45 70)"
echo "recon from ${ip} (enumerated app endpoints + ${n} sensitive-path probes)"
for ((i=1; i<=n; i++)); do hit GET "$(pick "${probes[@]}")" "$ip" "$ua"; done
