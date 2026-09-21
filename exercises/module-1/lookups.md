# Lookups: shapes and failures

## get_case.sh

    { "title": "...", "tags": ["rule:100151", "..."], "description": "...| Source IP | `192.0.2.1` |...",
      "srcip": "192.0.2.1", "observables": [ { "dataType": "ip", "data": "192.0.2.1" } ] }

`srcip` is read from the description table; it is `null` when the row is missing, then use the `ip` observable.

## wazuh_events.sh

    { "total": 14, "events": [ { "timestamp": "...", "rule": { "id": "100151", "level": 10, "description": "..." },
      "data": { "srcip": "192.0.2.1", "url": "/..." }, "agent": { "name": "wazuh.manager" } } ] }

Newest first. `total` is the count in the index, `events` at most 20.

## reputation.sh

`{"source":"abuseipdb","score":0-100,"reports":n}` with a key; 50 and above is flagged. Without a key: `{"source":"offline list, not live reputation","listed":true|false}`.

## post_verdict.sh

`{"_id":"~...","createdAt":...}` on success. Nothing else is written anywhere.

## Common issues

`THEHIVE_APIKEY: export THEHIVE_APIKEY first` from a script: the variable is not set in the shell that started `claude`. Export it from `THEHIVE_N8N_APIKEY` in `lab/.env` and restart `claude`.

`curl: (22) The requested URL returned error: 401` from `get_case.sh`: the key is wrong or stale. Same fix.

`curl: (22) ... error: 404` from `get_case.sh`: the id is missing its `~` prefix, or the case lives in another lab. Copy the id from the case URL in the browser.

`{"total": 0, "events": []}` from `wazuh_events.sh`: no events for that value. Retry with the `ip` observable; if still empty, write that the evidence is missing and choose `other`.

`curl: (7) Failed to connect` from `wazuh_events.sh`: `WAZUH_URL` points at the wrong port or the lab is down. `https://localhost:9200` is the indexer.

`grep: lab/threat-intel/malicious-ips.txt: No such file` from `reputation.sh`: `claude` was not started from the workshop folder. Restart it there, or export `LAB_DIR`.

The skill did not load on a natural-language prompt: the description lacks the words that were typed. Add them. `/soc-triage` bypasses the description and proves nothing about it.
