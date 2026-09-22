# Workflows

The n8n workflows for Modules 2 and 3, one folder per module. Each module has a skeleton you start from and a checkpoint you can import when a step costs more than five minutes, so nobody leaves without a working stack. Module 1 is a Claude Code skill, not a workflow, and its files are in `exercises/module-1/`.

| Module | Start from | Checkpoint (jump to if stuck) |
|--------|-----------|-------------------------------|
| Module 2 | `module-2/skeleton.json` (`SOC triage (skeleton)`) | `module-2/checkpoint.json` (`SOC triage, Module 2 checkpoint (LLM chain)`, `soctriagem2chk01`) |
| Module 3 | your own Module 2 workflow, duplicated | `module-3/checkpoint.json` (`SOC triage, Module 3 checkpoint (AI Agent)`, `soctriagem3chk01`) |

`start.sh` imports all three into n8n on every run. To use a checkpoint, open it in n8n, deactivate whatever else listens on `thehive-alert`, then activate it. Module 1's checkpoint is a finished Claude Code skill handed over by an instructor: copy it to `.claude/skills/soc-triage/`.

## One active webhook at a time

TheHive posts every event to `http://n8n:5678/webhook/thehive-alert`. n8n allows one active workflow per webhook path, so the skeleton and the two checkpoints cannot be active together. Deactivate the one you are leaving before activating the one you are entering.

## Credentials the workflows expect

| Name | id | Type | Value comes from |
|------|----|----|------------------|
| Wazuh indexer | credWazuhIndex01 | HTTP Basic Auth | `admin` / `brucon2026` (the indexer password in `docker-compose.yml`) |
| TheHive n8n | credTheHiveN8n01 | HTTP Header Auth | header `Authorization`, value `Bearer <THEHIVE_N8N_APIKEY>` that `start.sh` mints and writes to `lab/.env` |
| Model gateway | credModelGatewy1 | OpenAI API | `GATEWAY_API_KEY` and `GATEWAY_BASE_URL` from `lab/.env` |

`start.sh` creates all three with these fixed ids on every run, so the imported workflows link to them without any clicking.

## The answer is in the case, so the checkpoints hide it

The Wazuh integrator tags every case `kind:attack` or `kind:benign` and writes a `| Classification |` row into the description. Both checkpoints drop the tag and the row before the model sees the case (the `Extract case` node), and the Module 1 skill tells the model to ignore them. Leaving them in would let the model read the answer instead of working it out.

## Before you share a workflow

Exported workflow JSON carries credential names and ids and can carry auth headers. Never commit a real gateway key or TheHive key. The per-attendee key is injected at build time and revoked at session close (ADR-0002, ADR-0004).

## Checks

`python3 lab/workflows/check.py` verifies ids, credential ids, the shared prompt text and the webhook path. Run it after editing any workflow.
