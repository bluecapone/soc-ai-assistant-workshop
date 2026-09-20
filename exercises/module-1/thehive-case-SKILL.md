---
name: thehive-case
description: Fetch a case and its observables from TheHive, or write a comment to a case. Use when you need to read case details and attachments, query associated indicators, or post analysis back to a case.
allowed-tools: Bash(curl:*), Bash(jq:*)
---

## Task

Interact with TheHive cases: fetch a case by ID, query its observables (IOCs), or write a comment to a case.

## What you need

Export these environment variables before using this skill:

```bash
export THEHIVE_URL=http://<thehive-host>:9000
export THEHIVE_APIKEY=<api-key>
```

For example:
```bash
export THEHIVE_URL=http://localhost:9000
export THEHIVE_APIKEY=d1234567890abcdef1234567890abcdef12345678
```

The API key is a long alphanumeric string that TheHive generates for API users. Do not share it; treat it like a password.

## How to fetch a case

```bash
curl -s "$THEHIVE_URL/api/v1/case/$CASE_ID" \
  -H "Authorization: Bearer $THEHIVE_APIKEY"
```

Replace `$CASE_ID` with the case identifier, for example `~123456`.

## How to fetch a case's observables

```bash
curl -s -X POST "$THEHIVE_URL/api/v1/query" \
  -H "Authorization: Bearer $THEHIVE_APIKEY" \
  -H 'Content-Type: application/json' \
  -d '{"query":[{"_name":"getCase","idOrName":"'"$CASE_ID"'"},{"_name":"observables"}]}'
```

Replace `$CASE_ID` with the case identifier.

## How to write a comment to a case

First, prepare the comment text as a JSON string. For example, to write the content of the `$COMMENT_TEXT` variable:

```bash
curl -s -X POST "$THEHIVE_URL/api/v1/case/$CASE_ID/comment" \
  -H "Authorization: Bearer $THEHIVE_APIKEY" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg m "$COMMENT_TEXT" '{message:$m}')"
```

Replace `$CASE_ID` with the case identifier and `$COMMENT_TEXT` with the content to post. The `jq` command constructs the JSON payload safely, handling any special characters in the message.

## Response shape

### Case fetch response

```json
{
  "_id": "~123456",
  "number": 123456,
  "title": "SQL Injection Attempt",
  "description": "Attacker scanned the web server ...",
  "status": "Open",
  "severity": "High",
  "TLP": 2,
  "tags": ["web", "attack"],
  "template": "default"
}
```

### Observables response

```json
[
  {
    "data": "192.168.1.100",
    "dataType": "ip",
    "ioc": true,
    "tags": ["source"]
  },
  {
    "data": "example.com",
    "dataType": "domain",
    "ioc": true,
    "tags": []
  }
]
```

### Comment write response

Returns the created comment object with an `_id` field confirming the comment was posted.

## Common issues

- **Authentication fails** (`401 Unauthorized`): Check that `THEHIVE_APIKEY` is correct. The API key must match a user configured in TheHive.
- **Case not found** (`404 Not Found`): The case ID does not exist. Check that `$CASE_ID` is spelled correctly and in the format `~123456` (with the tilde).
- **Connection refused**: Confirm `THEHIVE_URL` is correct and TheHive is running.
- **Observables query returns empty array**: The case has no observables attached yet, or the case ID is wrong.
- **Comment write fails**: Verify the case ID exists, the API key is valid, and the comment text is valid JSON (use the `jq` construction shown above to ensure proper escaping).
