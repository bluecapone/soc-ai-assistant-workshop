# Workshop Guide

In this workshop you build a triage agent that ingests an alert, enriches it from your own telemetry, reasons about it with a hosted model, and writes a verdict into a case system. You run it against an intrusion you launch yourself, on your own laptop. Nothing is pre-recorded, and no part of the lab is shared with the room.

This manual is exercises only. Each exercise has a goal, the steps, what you should see, and a question whose answer proves you did it. The theory is on the slides.

```{toctree}
---
caption: Exercises
maxdepth: 2
hidden: true
---

02-connect.md
03-module-1.md
04-module-2.md
05-module-3.md
08-appendix-frontmatter.md
```

## Exercises

- [Module 0: Connect](02-connect.md)
  - [Exercise #0.1: bring up the lab](02-connect.md#exercise-01-bring-up-the-lab)
  - [Exercise #0.2: sign in everywhere](02-connect.md#exercise-02-sign-in-everywhere)
  - [Exercise #0.3: fire a benign button and follow it](02-connect.md#exercise-03-fire-a-benign-button-and-follow-it)
  - [Exercise #0.4: connect Claude Code to the gateway](02-connect.md#exercise-04-connect-claude-code-to-the-gateway)
  - [Exercise #0.5: connect the docs server](02-connect.md#exercise-05-connect-the-docs-server)
- [Module 1: drive it by hand](03-module-1.md)
  - [Exercise #1.1: the scripts, made from the docs](03-module-1.md#exercise-11-the-scripts-made-from-the-docs)
  - [Exercise #1.2: the references](03-module-1.md#exercise-12-the-references)
  - [Exercise #1.3: the asset](03-module-1.md#exercise-13-the-asset)
  - [Exercise #1.4: SKILL.md](03-module-1.md#exercise-14-skillmd)
  - [Exercise #1.5: test it](03-module-1.md#exercise-15-test-it)
  - [Exercise #1.6: share it](03-module-1.md#exercise-16-share-it)
- [Module 2: run it unattended](04-module-2.md)
  - [Exercise #2.1: what the skeleton already does](04-module-2.md#exercise-21-what-the-skeleton-already-does)
  - [Exercise #2.2: read the worked IP branch](04-module-2.md#exercise-22-read-the-worked-ip-branch)
  - [Exercise #2.3: add the hash branch](04-module-2.md#exercise-23-add-the-hash-branch)
  - [Exercise #2.4: add the domain branch](04-module-2.md#exercise-24-add-the-domain-branch)
  - [Exercise #2.5: check the three verdicts line up](04-module-2.md#exercise-25-check-the-three-verdicts-line-up)
  - [Exercise #2.6: the gather chain and the contract](04-module-2.md#exercise-26-the-gather-chain-and-the-contract)
  - [Exercise #2.7: fire it and walk away](04-module-2.md#exercise-27-fire-it-and-walk-away)
  - [Exercise #2.8: fix the text](04-module-2.md#exercise-28-fix-the-text)
- [Module 3: let it decide](05-module-3.md)
  - [Exercise #3.1: open the Module 3 skeleton](05-module-3.md#exercise-31-open-the-module-3-skeleton)
  - [Exercise #3.2: what the agent is given](05-module-3.md#exercise-32-what-the-agent-is-given)
  - [Exercise #3.3: read the three wired tools](05-module-3.md#exercise-33-read-the-three-wired-tools)
  - [Exercise #3.4: add the four missing tools](05-module-3.md#exercise-34-add-the-four-missing-tools)
  - [Exercise #3.5: fire it and read the trace](05-module-3.md#exercise-35-fire-it-and-read-the-trace)
  - [Exercise #3.6: you are the gate](05-module-3.md#exercise-36-you-are-the-gate)
- [Appendix: skill frontmatter](08-appendix-frontmatter.md)

## Prerequisites

Have these before Module 0:

- The *workshop folder*: a clone of [github.com/bluecapone/soc-ai-assistant-workshop](https://github.com/bluecapone/soc-ai-assistant-workshop) (Exercise 0.1 shows the command). Its name does not matter. It contains `guide/`, `exercises/` and `lab/`, and every command in this manual says which folder to run it from.
- Docker with Docker Compose ([install Docker Desktop](https://docs.docker.com/desktop/)), tested by running `./scripts/macos-linux/start.sh` (or `powershell -ExecutionPolicy Bypass -File .\scripts\windows\start.ps1` on Windows) from the lab directory. Podman is untested.
- 16 GB RAM and free disk for the compose stack.
- Claude Code installed.
- A gateway token, handed out at the door and revoked when the workshop ends.

You need to be able to read code. You never have to write any. Work is solo, with one or two co-instructors roaming the room.

## Your SOC for today

Every attendee runs an independent copy of the same six components. Nothing is shared.

| Component           | Role                                                                                        | Login                                 |
| ------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------- |
| TheHive             | Case management; your agent writes verdicts here                                            | `analyst@brucon.local` / `brucon2026` |
| n8n                 | Workflow orchestration for Modules 2 and 3                                                  | `admin@brucon.local` / `Brucon2026`   |
| Wazuh               | SIEM; collects live logs from bank-web and fires detections                                 | `admin` / `brucon2026`                |
| Range control panel | Attack console: nine attack buttons and six benign twins, all real commands against bank-web | none                                  |
| bank-web            | Deliberately vulnerable web application, the detection target                               | none                                  |
| Model gateway       | Every model call routes through it                                                          | your token, one per attendee          |

Configuration lives in `lab/.env`: `THEHIVE_N8N_APIKEY` (minted by the start script), `GATEWAY_BASE_URL`, `GATEWAY_API_KEY`, `MODEL_WEAK`, `MODEL_FRONTIER`. Model ids are announced from the slide on the day.

In n8n the gateway credential type is called "OpenAI API" because that protocol is a common standard several providers implement, not because OpenAI is involved. The two models behind the gateway are Gemini (`MODEL_WEAK`) and Claude (`MODEL_FRONTIER`), never GPT.

## Room rules

Solo work. One checkpoint per module. **Stuck for more than five minutes: take the module's checkpoint and move on.** The Module 2 and Module 3 checkpoints are already in n8n, inactive, named `SOC triage, Module 2 checkpoint (LLM chain)` and `SOC triage, Module 3 checkpoint (AI Agent)`. Activate the one you need and deactivate whatever else sits on the `thehive-alert` path. An instructor hands over the Module 1 one. Every module depends on the one before it, and falling behind costs you the rest of the module. Hands up. Pairing with a neighbour is normal, not failure.

## Guides for exercises

- `exercises/module-1/README.md`: the reference `soc-triage` skill files
- [TheHive API](https://docs.strangebee.com/thehive/api-docs/), [Wazuh indexer search](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html), [n8n docs](https://docs.n8n.io/)

## Safety

The attacks in this lab are real commands, not simulations. They run against `bank-web`, the deliberately vulnerable target container inside your compose stack on your laptop behind a single published port.

Do not aim any button, script or payload from this lab at the conference network, the venue, another attendee's machine, or any system you do not own. The lab gives you a safe place to watch an intrusion produce telemetry; that is the only place it belongs.
