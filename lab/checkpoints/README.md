# Checkpoints

A checkpoint is the known good solution for one module. The syllabus rule is that an attendee stuck for more than five minutes on a step imports the checkpoint and moves on, so nobody leaves without a working stack.

| Module | Artifact | n8n name and id | How to use |
|--------|----------|-----------------|-----------|
| Module 1 | handed over by an instructor (a Claude Code skill, not a workflow) | none | copy the folder you receive to `.claude/skills/soc-triage/`, then in Claude Code run `/soc-triage ~<caseId>` |
| Module 2 | `module-2/triage-m2-chain.json` | `SOC triage, Module 2 checkpoint (LLM chain)`, `soctriagem2chk01` | already imported by `start.sh`; open it in n8n, deactivate whatever else listens on `thehive-alert`, activate it |
| Module 3 | `module-3/triage-m3-agent.json` | `SOC triage, Module 3 checkpoint (AI Agent)`, `soctriagem3chk01` | same as Module 2 |

## Credentials the workflows expect

| Name | id | Type | Value comes from |
|------|----|----|------------------|
| Wazuh indexer | credWazuhIndex01 | HTTP Basic Auth | `admin` / `brucon2026` (the indexer password in `docker-compose.yml`) |
| TheHive n8n | credTheHiveN8n01 | HTTP Header Auth | header `Authorization`, value `Bearer <THEHIVE_N8N_APIKEY>`; `start.sh` mints the key and writes it to `lab/.env` |
| Model gateway | credModelGatewy1 | OpenAI API | `GATEWAY_API_KEY` and `GATEWAY_BASE_URL` from `lab/.env` |

`start.sh` creates all three with these fixed ids on every run, so the imported workflows link to them without any clicking.

## One active webhook at a time

TheHive posts every event to `http://n8n:5678/webhook/thehive-alert`. n8n allows one active workflow per webhook path, so the reference, the skeleton and the two checkpoints cannot be active together. Deactivate the one you are leaving before activating the one you are entering.

## The answer is in the case, so the checkpoints hide it

The Wazuh integrator tags every case `kind:attack` or `kind:benign` and writes a `| Classification |` row into the description. Both checkpoints drop the tag and the row before the model sees the case (the `Extract case` node), and the Module 1 skill tells the model to ignore them. Leaving them in would let the model read the answer instead of working it out.

## Before you share a workflow

Exported workflow JSON carries credential names and ids and can carry auth headers. Never commit a real gateway key or TheHive key. The per-attendee key is injected at build time and revoked at session close (ADR-0002, ADR-0004).

## Checks

`python3 lab/checkpoints/check.py` verifies ids, credential ids, the shared prompt text and the webhook path; run it after editing any checkpoint.
