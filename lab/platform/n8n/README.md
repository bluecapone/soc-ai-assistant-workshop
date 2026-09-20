# n8n workflows

## What is here

`triage-workflow.json` is a **plumbing reference**, not a turnkey workflow. It imports into n8n and wires the whole pipeline end to end so you can prove the seams:

```
Webhook (thehive-alert) -> Extract alert -> Enrich: Wazuh -> Enrich: OSINT
  -> LLM verdict (gateway) -> Write verdict to TheHive
```

It uses plain HTTP Request nodes for every step, including the LLM call, because that is the shape that is guaranteed to import cleanly and is easy to verify. The attendee's actual build in Modules 2 and 3 replaces the LLM node with n8n's LLM cluster nodes (see [Module progression](#module-progression)). Treat this file as the instructor's reference and the checkpoint import, per the syllabus.

## Verify on live n8n (this is the other load-bearing seam)

1. Import `triage-workflow.json` (Workflows > Import from File).
2. `start.sh` provisions the three credentials it references: **Wazuh indexer** (`credWazuhIndex01`), **TheHive n8n** (`credTheHiveN8n01`), **Model gateway** (`credModelGatewy1`). Create them by hand only when running n8n without the script:
   - **Wazuh indexer** (HTTP Basic Auth): user `admin`, the indexer password from `.env`.
   - **TheHive n8n** (HTTP Header Auth): header `Authorization`, value `Bearer <THEHIVE_N8N_APIKEY>`.
3. Confirm the environment variables reach n8n: `GATEWAY_BASE_URL`, `GATEWAY_API_KEY`, `MODEL_WEAK`, and (optional) `OSINT_API_KEY`. They are passed in `docker-compose.yml`.
4. Activate the workflow so the production webhook URL `…/webhook/thehive-alert` is live, then confirm TheHive's notifier points at it (`thehive/application.conf`).
5. Fire a button on the range control panel and watch the execution: the webhook receives the TheHive event, enrichment runs, the gateway returns a verdict, and the verdict is written back to TheHive.

The **TheHive webhook payload shape** is the thing most likely to need adjusting. The `Extract alert` node reads `$json.body.object.{title,description,tags,observables}`; confirm those paths against a real event (pin the webhook, inspect one execution's input) and fix the expressions if the shape differs. This is expected work, not a defect.

## Module progression

The reference above is Module 2 shaped (a single-pass narrative). The teaching build swaps the LLM node as autonomy increases, per the syllabus and ADR-0004:

- **Module 2** — replace `LLM verdict (gateway)` with a **Basic LLM Chain** node plus an **OpenAI Chat Model** sub-node. Set the chat model's credential **Base URL** to `GATEWAY_BASE_URL` and the model to `gemini-3.5-flash-lite` (free-text entry works even if the gateway does not enumerate it). Add a **Structured Output Parser** enforcing the three-section schema (`summary`, `suggested_close_state`, `recommended_actions`). See the reference checkpoint at `lab/checkpoints/module-2/triage-m2-chain.json`.
- **Module 3** — replace it with the **AI Agent** node (Tools Agent) and connect the enrichment lookups as **tool** sub-nodes, so the model itself decides which to call. Switch the model to `claude-sonnet-5`. See the reference checkpoint at `lab/checkpoints/module-3/triage-m3-agent.json`.

**Tool calling through a base-URL override fails silently** (ADR-0004). Confirm the tool was actually invoked; do not trust "no error" as success.

## Sanitize before sharing

Exported workflow JSON carries credential *names and ids* and can carry auth headers. Never commit a real gateway key or TheHive key. The per-attendee key is injected at build time and revoked at session close (ADR-0002, ADR-0004).
