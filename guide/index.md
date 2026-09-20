# Attendee manual

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
07-take-home.md
```

## Exercises

- [Part 0: Connect](02-connect.md)
  - Exercise #0.1: bring up the lab
  - Exercise #0.2: sign in everywhere
  - Exercise #0.3: fire a benign button and follow it
- [Part 1: Module 1, drive it by hand](03-module-1.md)
  - Exercise #1.1: connect Claude Code to the gateway
  - Exercise #1.2: draft the skill and edit it by hand
  - Exercise #1.3: give it Wazuh
  - Exercise #1.4: give it TheHive
  - Exercise #1.5: fire an alert and drive it by hand
  - Exercise #1.6: run it again on a twin
  - Exercise #1.7: does the skill load?
  - Exercise #1.8: extract reusable skills
  - Exercise #1.9, bonus: add a reputation lookup
- [Part 2: Module 2, run it unattended](04-module-2.md)
- [Part 3: Module 3, let it decide](05-module-3.md)
- [Take-home](07-take-home.md)

## Prerequisites

Have these before Part 0:

- The *workshop folder*: a clone of [github.com/bluecapone/soc-ai-assistant-workshop](https://github.com/bluecapone/soc-ai-assistant-workshop) (Exercise 0.1 shows the command). Its name does not matter. It contains `guide/`, `exercises/` and `lab/`, and every command in this manual says which folder to run it from.
- Docker with Docker Compose ([install Docker Desktop](https://docs.docker.com/desktop/)), tested by running `./scripts/start.sh` (or `start.ps1`) from the lab directory. Podman is untested.
- 16 GB RAM and free disk for the compose stack.
- Claude Code installed.
- A gateway token, handed out at the door and revoked when the workshop ends.

You need to be able to read code. You never have to write any. Work is solo, with one or two co-instructors roaming the room.

## Your SOC for today

Every attendee runs an independent copy of the same six components. Nothing is shared.

| Component | Role | Login |
|---|---|---|
| TheHive | Case management; your agent writes verdicts here | `analyst@brucon.local` / `brucon2026` |
| n8n | Workflow orchestration for Modules 2 and 3 | `admin@brucon.local` / `Brucon2026` |
| Wazuh | SIEM; collects live logs from bank-web and fires detections | `admin` / `brucon2026` |
| Range control panel | Attack console: ten attack buttons and six benign twins, all real commands against bank-web | none |
| bank-web | Deliberately vulnerable web application, the detection target | none |
| Model gateway | Every model call routes through it | your token, one per attendee |

Configuration lives in `lab/.env`: `THEHIVE_N8N_APIKEY` (minted by the start script), `GATEWAY_BASE_URL`, `GATEWAY_API_KEY`, `MODEL_WEAK`, `MODEL_FRONTIER`. Model ids are announced from the slide on the day.

In n8n the gateway credential type is called "OpenAI API" because that protocol is a common standard several providers implement, not because OpenAI is involved. The two models behind the gateway are Gemini (`MODEL_WEAK`) and Claude (`MODEL_FRONTIER`), never GPT.

## Room rules

Solo work. One checkpoint per module. **Stuck for more than five minutes: take the module's checkpoint and move on.** Every module depends on the one before it, and falling behind costs you the rest of the module. Hands up. Pairing with a neighbour is normal, not failure.

## Guides for exercises

- `lab/exercises/README.md`: starting artifacts and checkpoints per module
- `lab/checkpoints/README.md`: how to use each checkpoint, credentials the workflows expect
- `skills/README.md`: the finished `wazuh-query` and `thehive-case` skills
- `instructor-docs/`: the theory behind each part, as background reading
- [TheHive API](https://docs.strangebee.com/thehive/api-docs/), [Wazuh indexer search](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html), [n8n docs](https://docs.n8n.io/)

## Safety

The attacks in this lab are real commands, not simulations. They run against `bank-web`, the deliberately vulnerable target container inside your compose stack on your laptop behind a single published port.

Do not aim any button, script or payload from this lab at the conference network, the venue, another attendee's machine, or any system you do not own. The lab gives you a safe place to watch an intrusion produce telemetry; that is the only place it belongs.
