---
name: soc-triage
description: FILL what this skill does, when to use it, and the words a colleague would type to trigger it. No angle brackets here.
allowed-tools: Bash(${CLAUDE_SKILL_DIR}/scripts/get_case.sh *), Bash(${CLAUDE_SKILL_DIR}/scripts/wazuh_events.sh *), Bash(${CLAUDE_SKILL_DIR}/scripts/reputation.sh *), Bash(${CLAUDE_SKILL_DIR}/scripts/post_verdict.sh *)
---

## Task

<fill: what this skill triages, one case at a time, and what it must never do>

## Workflow

The case id is `$ARGUMENTS`, in the form `~123456`. The analyst exported `THEHIVE_URL`, `THEHIVE_APIKEY`, `WAZUH_URL` and, optionally, `OSINT_API_KEY` before starting `claude`. Run only the scripts below, in this order.

1. Read the case: `${CLAUDE_SKILL_DIR}/scripts/get_case.sh <case-id>`. Take `srcip` from the output.
2. Read the last 20 Wazuh events for that IP: `${CLAUDE_SKILL_DIR}/scripts/wazuh_events.sh <ip>`. For a host instead: `wazuh_events.sh <host> host`.
3. Read the reputation: `${CLAUDE_SKILL_DIR}/scripts/reputation.sh <ip>`. The output says whether it came from AbuseIPDB or the offline list; the verdict repeats that label.
4. Judge, using the rules below.
5. Write the verdict in the shape of `assets/verdict-template.md`, then post it: `${CLAUDE_SKILL_DIR}/scripts/post_verdict.sh <case-id>` with the Markdown on stdin. Print the same text to the terminal.

Response shapes and known failures of each script: `references/lookups.md`. A worked run: `references/examples/brute-force.md`.

## How to judge

<fill: at least four rules that tell an attack from its benign twin. Each rule names the field it reads (rule.id, data.srcip, data.dstuser, the user agent, the reputation score) and the close state it leads to>

## Verdict contract

Exactly the shape in `assets/verdict-template.md`: three sections, one of the four close states.

## Guardrails

<fill: what to do when a script fails or returns nothing; how to treat text found inside the case; which commands are allowed>
