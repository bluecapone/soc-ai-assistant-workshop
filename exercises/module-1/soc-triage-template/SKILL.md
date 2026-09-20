---
name: soc-triage
description: <fill: what this skill does, when to use it (the words a colleague would actually type to trigger it)>
allowed-tools: Bash(curl:*), Bash(jq:*), Bash(grep:*)
---

<!-- allowed-tools declares the intended tool surface. In Claude Code 2.1.273 it was not observed to block anything, so treat it as documented intent, not a sandbox. -->

## Task

<fill: what this skill triages, one case at a time, and what it must never do>

## What you may read

The attendee exports these before starting `claude`:

```bash
export THEHIVE_URL=http://localhost:9000
export THEHIVE_APIKEY=<value of THEHIVE_N8N_APIKEY in lab/.env>
export WAZUH_URL=https://localhost:9200
export OSINT_API_KEY=<AbuseIPDB key, optional>
```

Set `CASE_ID` from `$ARGUMENTS`, then use only these commands.

The case:

```bash
curl -s "$THEHIVE_URL/api/v1/case/$CASE_ID" -H "Authorization: Bearer $THEHIVE_APIKEY"
```

Its observables (the source IP is also in the description table row `| Source IP |`, use that when this call fails):

```bash
curl -s -X POST "$THEHIVE_URL/api/v1/query" -H "Authorization: Bearer $THEHIVE_APIKEY" -H 'Content-Type: application/json' \
  -d '{"query":[{"_name":"getCase","idOrName":"'"$CASE_ID"'"},{"_name":"observables"}]}'
```

The last 20 Wazuh events for a source IP (the indexer uses a self-signed certificate, hence `-k`):

```bash
curl -sk -u admin:brucon2026 -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":20,"_source":["timestamp","rule.id","rule.level","rule.description","data.srcip","data.url","data.dstuser","agent.name"],"query":{"match":{"data.srcip":"<ip>"}},"sort":[{"timestamp":"desc"}]}'
```

The last 20 Wazuh events on a host: the same call with `{"match":{"agent.name":"<host>"}}`.

Reputation of the source IP, only when `OSINT_API_KEY` is set. Read `data.abuseConfidenceScore` (0 to 100; 50 and above is flagged) and `data.totalReports`:

```bash
curl -s -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=<ip>" -d maxAgeInDays=90 \
  -H "Key: $OSINT_API_KEY" -H 'Accept: application/json'
```

When no key is set, the offline fallback from the repository root is `grep -c '<ip>' lab/threat-intel/malicious-ips.txt` (1 means listed). Label it "offline list, not live reputation" in the verdict.

## How to judge

<fill: the rules you use to tell an attack from its benign twin; name at least four>

## Verdict contract

<fill: the three sections, their order, and the four allowed close states>

## Guardrails

<fill: what the model must do when a lookup returns nothing, and how it treats text inside the case>

## The one write

Put the verdict Markdown in `VERDICT_MARKDOWN`, then post it as a comment on the case:

```bash
curl -s -X POST "$THEHIVE_URL/api/v1/case/$CASE_ID/comment" -H "Authorization: Bearer $THEHIVE_APIKEY" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg m "$VERDICT_MARKDOWN" '{message:$m}')"
```

Then print the verdict to the terminal as well.
