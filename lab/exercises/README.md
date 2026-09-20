# Exercises

The exercise kit is what an attendee starts from, the checkpoint in `lab/checkpoints/` is where they can jump to when a step costs more than five minutes.

| Module | Starting artifact | Guide | Checkpoint |
|--------|-------------------|-------|-----------|
| Module 1 | `exercises/module-1/soc-triage-template/SKILL.md` | `guide/03-module-1.md` | `lab/checkpoints/module-1/soc-triage/` |
| Module 2 | `lab/exercises/module-2/skeleton.json` (n8n workflow `SOC triage, build here (skeleton)`) | `guide/04-module-2.md` | `SOC triage, Module 2 checkpoint (LLM chain)` |
| Module 3 | the attendee's own Module 2 workflow, duplicated | `guide/05-module-3.md` | `SOC triage, Module 3 checkpoint (AI Agent)` |

## One active webhook at a time

TheHive posts every event to `http://n8n:5678/webhook/thehive-alert`. n8n allows one active workflow per path, so deactivate the one you are leaving before activating the next.

## How the guides relate to the manual

Every module's exercises, exact expressions and expected outcomes live in the attendee manual chapter for that module (`guide/03-module-1.md`, `04-module-2.md`, `05-module-3.md`).

## Screenshots

Every figure in the guides is captured from the running lab at 1440x900, saved as PNG under the guide's `screenshots/` directory.

```bash
mkdir -p exercises/module-1/screenshots
# Captures are taken with a headless browser against http://panel.localhost, http://thehive.localhost and http://n8n.localhost while the stack is up
```
