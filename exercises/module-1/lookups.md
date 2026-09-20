# Lookups: shapes and failures

## get_case.sh

```json
{ "title": "...", "tags": ["rule:100151", "..."], "description": "...| Source IP | `192.0.2.1` |...",
  "srcip": "192.0.2.1", "observables": [ { "dataType": "ip", "data": "192.0.2.1" } ] }
```

`srcip` is read from the description table; it is `null` when the row is missing, then use the `ip` observable.

## wazuh_events.sh

```json
{ "total": 14, "events": [ { "timestamp": "...", "rule": { "id": "100151", "level": 10, "description": "..." },
  "data": { "srcip": "192.0.2.1", "url": "/..." }, "agent": { "name": "wazuh.manager" } } ] }
```

Newest first. `total` is the count in the index, `events` at most 20.

## reputation.sh

`{"source":"abuseipdb","score":0-100,"reports":n}` with a key; 50 and above is flagged. Without a key: `{"source":"offline list, not live reputation","listed":true|false}`.

## post_verdict.sh

`{"_id":"~...","createdAt":...}` on success. Nothing else is written anywhere.

## Common issues

<fill: one entry per failure you met by hand in Exercises 1.3 and 1.4: the error text, its cause, the fix>
