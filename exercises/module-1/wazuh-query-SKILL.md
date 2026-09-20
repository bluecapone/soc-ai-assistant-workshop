---
name: wazuh-query
description: Use when hunting or investigating in a Wazuh/OpenSearch indexer — search alerts by source IP, host, rule id, rule group, log type, or time window; correlate one source's activity across events (for example whether an IP that brute-forced SSH also had a successful login); or work out what a detection means. Covers every lab log type — web, SSH, mail, proxy, data transfer, and internal host telemetry.
allowed-tools: Bash(curl:*), Bash(jq:*)
---

## Task

Search and correlate alerts in a Wazuh indexer to answer hunting and investigation questions. This skill is **read-only**: it only searches. It never writes to Wazuh, and it does no reputation/OSINT lookups and no case management — those belong to other skills.

## What you need

Export these before using the skill. The defaults are the workshop lab; override them to point at another deployment.

```bash
export WAZUH_URL=https://localhost:9200
export WAZUH_USERNAME=admin
export WAZUH_PASSWORD=brucon2026
```

All examples use `curl -k` because the indexer serves a self-signed certificate. Alerts live in daily indices `wazuh-alerts-4.x-YYYY.MM.DD`; search the wildcard `wazuh-alerts-*` to cover every day at once.

A reusable base for every call:

```bash
wz() { curl -s -k -u "$WAZUH_USERNAME:$WAZUH_PASSWORD" "$@"; }
```

## Log types available

Each event carries a `decoder.name` (the parser), a `location` (the source file), and typed `data.*` fields. These are the log types in the lab and the fields worth querying on:

| decoder.name | location | what it is | key `data.*` fields |
|---|---|---|---|
| `bankweb-access` | `/var/log/bank-web/access.log` | web requests | `srcip`, `method`, `url`, `id` (HTTP status), `bytes`, `user_agent` |
| `bankweb-auth` | `/var/log/bank-web/auth.log` | web logins | `srcip`, `dstuser`, `authresult` (`success`/`failure`) |
| `sshd` | `/var/log/host/auth.log` | SSH auth | `srcip`, `dstuser`, `srcport` |
| `mailscan` | `.../mail-gateway-01/maillog` | mail gateway | `mail_from`, `srcip`, `mail_to`, `verdict`, `url`, `attachment`, `sha256` |
| `proxy` | `.../proxy-01/proxy.log` | web egress | `srcip`, `dstip`, `dst_host`, `port`, `bytes`, `user_agent`, `cat`, `action` |
| `dataxfer` | `.../web-prod-01/...` | host-to-host transfers | `srcip`, `dstip`, `dst_host`, `bytes`, `user_agent` |
| `windows-security` | `.../dc-01/security.log` | AD domain logons | `host`, `win_event`, `user`, `logon_type`, `src_ip`, `workstation`, `status` |
| `postgresql` | `.../database-01/postgresql.log` | database | `host`, `db_user`, `database`, `statement_kind`, `rows`, `src_ip` |
| `samba` | `.../fileserver-01/smbd.log` | file shares | `host`, `user`, `share`, `path`, `op`, `src_ip` |
| `openvpn` | `.../vpn-corp-01/openvpn.log` | VPN sessions | `host`, `user`, `src_ip`, `event` |
| `edr` | `.../workstation-*/edr.log` | endpoint | `host`, `user`, `event`, `detail` |
| `veeam` | `.../backup-01/veeam.log` | backup jobs | `host`, `job`, `status`, `bytes` |

**Source-IP field gotcha:** the decoder-parsed attack/twin chain (web, SSH, mail, proxy, data transfer) carries the source as **`data.srcip`**. The internal-host telemetry band (rules 100201–100208, written straight to the indexer) uses **`data.src_ip`** with an underscore. Attack hunts key on `data.srcip`; only reach for `data.src_ip` when querying that host-telemetry band.

## Rule bands: signal vs noise

The `rule.groups` array is the fastest way to separate real detections from background. A hunt for threats filters on the `attack` group; everything on `ambient` is generated noise that never becomes a case.

| Band | rule.id | Meaning | group |
|---|---|---|---|
| Attack chain | 100100 recon · 100110 SQLi · 100120 web brute force · 100130 RCE · 100131 web shell · 100140 C2 · 100142 exfil · 100150 path traversal · 100160 SSH brute force · 100170 phishing | the real intrusion | `attack` |
| Benign twins | 100121 successful web login · 100141 CDN callout · 100143 backup · 100151 crawler · 100161 SSH login success · 100171 clean email | same shape, harmless — decide by **source IP** | `benign` |
| Ambient noise | 100200 public web · 100201–100208 internal host telemetry · 100221–100225 incident breadcrumbs | generated, never forwarded to a case | `ambient` |
| Intermediate | 100090 (404) · 100119 (web login failure) · 100152 (crawler hit) | building blocks, not cases | — |
| Wazuh built-in SSH | 5760 failed password · 5715 accepted · 5763 brute-force composite | raw sshd events | `sshd` |

Note that `100161` (SSH login success) is **shared** between the attack (a compromise from the attacker IP) and its benign twin (an engineer logging in from the internal IT workstation). The rule id alone cannot tell them apart — the source IP and whether a brute force preceded it can.

## How to search

Fields `rule.id`, `rule.groups`, `decoder.name`, `location`, and `data.srcip` are keyword-mapped, so `term`/`terms` queries and aggregations work directly on them.

Search by **source IP**, newest first:

```bash
wz -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 50,
  "sort": [{"timestamp": "desc"}],
  "_source": ["timestamp","rule.id","rule.level","rule.description","decoder.name","data.srcip","data.dstuser","data.url","data.authresult"],
  "query": {"term": {"data.srcip": "223.159.80.211"}}
}'
```

Swap the `query` for any of these:

```jsonc
// by host / agent
{"term": {"agent.name": "web-prod-01"}}
// by a specific rule
{"term": {"rule.id": "100160"}}
// only real attack detections (the core threat hunt)
{"term": {"rule.groups": "attack"}}
// one log type
{"term": {"decoder.name": "sshd"}}
// free text anywhere in the raw line
{"match": {"full_log": "etc/passwd"}}
// a time window (last 2 hours)
{"range": {"@timestamp": {"gte": "now-2h"}}}
```

Combine conditions with `bool`. Recent attacks on one host in the last hour:

```bash
wz -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 50, "sort": [{"timestamp": "desc"}],
  "query": {"bool": {"filter": [
    {"term": {"rule.groups": "attack"}},
    {"range": {"@timestamp": {"gte": "now-1h"}}}
  ]}}
}'
```

Aggregate to profile at a glance — e.g. top source IPs among attack detections:

```bash
wz -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"term": {"rule.groups": "attack"}},
  "aggs": {"ips": {"terms": {"field": "data.srcip", "size": 20}}}
}'
```

## Correlate one source across events

The most useful hunt asks what a single IP *did*, not what one event *was*. **"Did IP X have a successful login while brute-forcing SSH?"** — the decisive answer is whether that source produced **both** a brute-force detection **and** a success from the same address. Check that directly; use a timeline only to narrate it.

**Decisive check — does the IP show both a brute id and a success id?** Aggregate its rule ids:

```bash
IP=223.159.80.211
wz -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"term": {"data.srcip": "'"$IP"'"}},
  "aggs": {"rules": {"terms": {"field": "rule.id",
                               "include": ["100120","100121","100160","100161"],
                               "size": 10}}}
}'
```

A source with **both** a brute-force id (100120 web / 100160 SSH) **and** a success id (100121 web / 100161 SSH) both attacked and got in — a compromise, not a benign login. Equivalently, by group: `brute_force`/`authentication_failures` together with `authentication_success` from one `data.srcip`.

**Pull the success itself** to see which account fell and the raw line:

```bash
wz -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 10, "sort": [{"timestamp": "desc"}],
  "_source": ["timestamp","rule.id","data.dstuser","full_log"],
  "query": {"bool": {"filter": [
    {"term": {"data.srcip": "'"$IP"'"}},
    {"term": {"rule.id": "100161"}}
  ]}}
}'
```

For the web login pipeline use rule `100121` instead of `100161` (or filter `decoder.name: bankweb-auth` and read `data.authresult`).

**Narrate the story in order** — pull the IP's SSH events oldest-first to show the spray leading to the breakthrough:

```bash
wz -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{
  "size": 300, "sort": [{"timestamp": "asc"}],
  "_source": ["timestamp","rule.id","rule.description","data.dstuser"],
  "query": {"bool": {"filter": [
    {"term": {"data.srcip": "'"$IP"'"}},
    {"term": {"decoder.name": "sshd"}}
  ]}}
}'
```

**Caveat:** the lab's authored SSH and mail logs are stamped at one-second granularity, so a whole burst can share a single timestamp and will not strictly tail-sort. Treat the two checks above (both-ids present, and pulling the success directly) as the verdict; use this timeline to illustrate it, not to prove ordering.

## Response shape

Events are under `.hits.hits[]._source`; aggregation buckets under `.aggregations.<name>.buckets[]`. An empty `hits.hits` array (or empty buckets) means nothing matched — not an error. Pipe through `jq` to shape output, e.g. `... | jq '.hits.hits[]._source | {t:.timestamp, id:.rule.id, d:.rule.description, ip:.data.srcip}'`.

## Common issues

- **401 Unauthorized**: `WAZUH_USERNAME`/`WAZUH_PASSWORD` wrong, or the user does not exist in the indexer.
- **SSL certificate error**: the indexer is self-signed; keep the `-k` flag. Check `WAZUH_URL` (scheme is `https`, port `9200`).
- **0 matches**: widen the time range, confirm the field/value (IPs are `data.srcip`, SSH users are `data.dstuser`), and search `wazuh-alerts-*` rather than a single day's index.
- **"Text fields are not optimised…" on an aggregation**: aggregate on a keyword-mapped field. `rule.id`, `rule.groups`, `decoder.name`, `location`, and `data.srcip` all aggregate directly.
- **index_not_found_exception**: no `wazuh-alerts-*` indices exist yet — nothing has been ingested.
