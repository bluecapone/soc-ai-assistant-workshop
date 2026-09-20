# Part 1: Module 1, drive it by hand

You author a Claude Code skill that triages one TheHive case and writes a verdict back to it. A skill is prompt text plus a tool surface: what the task is, how to judge a good answer, which lookups are permitted. You write it as a file in your repository, so a colleague can read it and argue with it in code review.

Every verdict in this workshop has the same three sections: a summary, a suggested close state (true positive, false positive, true positive but not malicious, or other) and recommended actions. The skill reads Wazuh and TheHive; its only write is one comment on the case.

## Exercise #1.1: connect Claude Code to the gateway

**Goal**: Claude Code answers a prompt through the workshop gateway with your token, started from the workshop folder with the skill template in place.

Every model call goes through one *gateway* the instructors run. Claude Code reads two environment variables for it; any client that reads the same two variables uses the gateway too.

1. **Gateway.** Export the gateway address (announced from the slide) and the token you got at the door. macOS or Linux:

   ```bash
   export ANTHROPIC_BASE_URL=<gateway URL from the slide>
   export ANTHROPIC_AUTH_TOKEN=<your token>
   ```

   Windows PowerShell:

   ```powershell
   $env:ANTHROPIC_BASE_URL = "<gateway URL from the slide>"
   $env:ANTHROPIC_AUTH_TOKEN = "<your token>"
   ```

2. **Lab credentials.** From the workshop folder, export the values the skill uses. `THEHIVE_N8N_APIKEY` in `lab/.env` is a real key after Exercise 0.1, not `replace-after-first-boot`. Nothing reads `lab/.env` for you: Docker Compose uses it, your shell does not.

   ```bash
   export THEHIVE_URL=http://localhost:9000
   export THEHIVE_APIKEY=$(grep THEHIVE_N8N_APIKEY lab/.env | cut -d= -f2-)
   export WAZUH_URL=https://localhost:9200
   ```

3. **Skill in place.** Still from the workshop folder, copy the skill template into the folder Claude Code reads skills from, then start Claude Code here. <ins>Start Claude Code from the workshop folder every time</ins>; the skill is only found from here.

   ```bash
   mkdir -p .claude/skills
   cp -r exercises/module-1/soc-triage-template .claude/skills/soc-triage
   claude
   ```

4. **Test.** Send one test prompt: `what is 2+2?`

**Expected**: Claude Code answers. A `401` means the token is wrong or expired; ask an instructor for a new one.

To keep the variables across terminals, add the export lines to `~/.zshrc` or `~/.bash_profile`. On Windows, use the *Environment Variables* control panel.

**Question 1**: what did the test prompt answer?

## Exercise #1.2: draft the skill and edit it by hand

**Goal**: `.claude/skills/soc-triage/SKILL.md` has every `<fill: ...>` answered in your own words.

The template already names the lookups. The fills are the parts only you can write: what the skill is for, how it tells an attack from its benign twin, the verdict shape, and what it does when a lookup comes back empty.

1. Give Claude Code a detailed instruction to draft the fills. A worked one:

   ```text
   Fill every <fill: ...> marker in .claude/skills/soc-triage/SKILL.md. The skill triages one TheHive case at a time, given a case id like ~123456. It reads the case from TheHive and the last 20 Wazuh events for the case's source IP (web requests, authentication, SSH logins, email). It writes a verdict with three sections: summary, suggested close state (true positive, false positive, true positive not malicious, other), recommended actions. It must not write to Wazuh, close or modify the case, or make any change other than one comment on the case. Keep the commands that are already in the file.
   ```

   Weak instructions fail in different ways. "Write a security skill" is too vague. "Write a skill that reads Wazuh" names the source but not the job. "No external lookups" forbids the lookups you need.

2. Open the file and read every line. Cut what is wrong or unclear. Tighten vague language: "check the logs for suspicious activity" becomes "read the Wazuh events for authentication failures from the same source before the success". You own the text.

Expected: no `<fill:` left in the file, and at least four rules under `How to judge`.

**Question 2**: one sentence you rewrote, before and after.

## Exercise #1.3: give it Wazuh

**Goal**: you have run the skill's Wazuh lookup by hand and know what it returns.

The Wazuh indexer is a search endpoint over every alert the range produced. It serves TLS with a self-signed certificate, hence `-k`. The skill will run this same command and read the same output.

1. Read the Wazuh block under `What you may read` in `SKILL.md`.
2. In a second terminal (with the same exports), run it with the source IP from your Part 0 case in place of `<ip>`:

   ```bash
   curl -sk -u admin:brucon2026 -X POST "$WAZUH_URL/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
     -d '{"size":20,"_source":["timestamp","rule.id","rule.level","rule.description","data.srcip","data.url","data.dstuser","agent.name"],"query":{"match":{"data.srcip":"<ip>"}},"sort":[{"timestamp":"desc"}]}' | jq '.hits.hits[]._source'
   ```

Expected: the matching events, newest first. The skill reads this to answer: how much activity is there from this source, and is it routine or anomalous?

**Question 3**: `rule.id` of the newest event for that IP.

## Exercise #1.4: give it TheHive

**Goal**: you have run the skill's TheHive read by hand and know where the verdict will land.

TheHive is the only system the skill writes to, and the only write is a comment. Closing the case is a different call this workshop never makes.

1. Read the two case blocks and `The one write` in `SKILL.md`.
2. Run the case read with the case id from Part 0:

   ```bash
   CASE_ID=~<case id>
   curl -s "$THEHIVE_URL/api/v1/case/$CASE_ID" -H "Authorization: Bearer $THEHIVE_APIKEY" | jq '{title, tags, description}'
   ```

3. Do not run the write. The skill does that in Exercise 1.5.

Expected: the case title, its tags and the description with the indicator table.

## Exercise #1.5: fire an alert and drive it by hand

**Goal**: your skill has triaged one attack case and its verdict is a comment on the case.

You trigger every step yourself. Nothing happens unless you ask for it.

1. On the panel, click `Brute force` and confirm. In TheHive, copy the new case id.
2. In Claude Code:

   ```text
   /soc-triage ~<case id>
   ```

3. Watch it read the case, look up the source IP in Wazuh, reason, and post the verdict.
4. Open the case in TheHive. Confirm the comment carries three sections and reads clearly to someone who did not watch you work. From the API:

   ```bash
   curl -s -X POST "$THEHIVE_URL/api/v1/query" -H "Authorization: Bearer $THEHIVE_APIKEY" -H 'Content-Type: application/json' \
     -d '{"query":[{"_name":"getCase","idOrName":"'"$CASE_ID"'"},{"_name":"comments"}]}' | jq '.[].message'
   ```

Expected: the terminal shows a verdict with three `###` sections and the same text is one comment on the case.

**Question 4**: the case id.

**Question 5**: the close state the skill chose.

## Exercise #1.6: run it again on a twin

**Goal**: the skill gives the benign twin a different close state.

`Admin login` is the twin of `Brute force`: a real admin mistypes, then succeeds. Same log shape, harmless intent.

1. On the panel, click `Admin login` and confirm. Copy the new case id.
2. Run `/soc-triage ~<case id>` again.

Expected: a different close state from Exercise 1.5. If both verdicts match, the rules under `How to judge` are too loose: tighten one, rerun, compare.

Exercises 1.5 and 1.6 are the skill-authoring loop: fire a real scenario, tighten the wording on what you learned, fire the twin, confirm the outcome changed.

**Question 6**: did the close state change? If not, which rule did you tighten?

## Exercise #1.7: does the skill load?

**Goal**: the description triggers the skill on natural language, and only then.

Claude Code loads a skill when the prompt matches its description. `/soc-triage` bypasses the description entirely, so it proves nothing about it.

1. Run each prompt. The skill should load.
   - `triage case ~<case id>`
   - `work the newest case in TheHive`
   - `is this alert a false positive`
2. Run each prompt. The skill should not load.
   - `what is our mean time to respond`
   - `summarise this pcap`
3. Change the description to `Helps with things`, save, and run one should-load prompt again. Restore the description and run it once more.

Expected: the three should-load prompts load it, the two others do not, and the useless description stops the natural-language prompt from loading it.

**Question 7**: which prompt, if any, failed to load it?

## Exercise #1.8: extract reusable skills

**Goal**: the Wazuh lookup and the TheHive read and write are standalone skills you can install anywhere.

Nothing in those lookups is specific to triage. The finished versions are `skills/wazuh-query/SKILL.md` and `skills/thehive-case/SKILL.md` in this repository; yours do not need to match them, but they should cover the same ground.

1. Write `wazuh-query`: how to search by IP and by hostname, what the response looks like, common failure modes.
2. Write `thehive-case`: how to fetch a case, fetch its observables, write a comment, with response shapes and failure modes.
3. Parameterise credentials (`$WAZUH_USERNAME` instead of `admin`) so they work outside this lab.
4. Install both from the workshop folder and list them:

   ```bash
   npx skills add <path to the workshop folder> --skill wazuh-query --agent claude-code
   npx skills add <path to the workshop folder> --skill thehive-case --agent claude-code
   npx skills list
   ```

To share, push the repository to GitHub and install with `npx skills add <your-username>/<repo-name> --skill wazuh-query --agent claude-code`. GitLab URLs are not documented for `npx skills add`; they may work through git's own URL parsing, but the error messages will be misleading. Use GitHub.

Expected: both skills appear in `npx skills list` and load when called.

**Question 8**: the output of `npx skills list`.

## Exercise #1.9, bonus: add a reputation lookup

**Goal**: the verdict cites the source IP's reputation, from a live API or the offline list.

Enrichment is not only your own telemetry. The template already carries the AbuseIPDB call and the offline fallback.

1. Export a key if you have one: `export OSINT_API_KEY=<AbuseIPDB key>`. Free tier is 1000 requests a day.
2. Run the reputation block from `SKILL.md` for the attacker IP by hand. With no key, run the fallback: `grep -c '<ip>' lab/threat-intel/malicious-ips.txt` (1 means listed).
3. Add a judging rule that uses the score, then rerun `/soc-triage` on the Exercise 1.5 case.

Expected: the summary names the reputation, labelled "offline list, not live reputation" when the fallback was used.

**Question 9**: `abuseConfidenceScore` for the attacker IP, or "offline list".

## Stuck five minutes?

From the workshop folder, copy the checkpoint skill over your template and run the same command:

```bash
cp -r lab/checkpoints/module-1/soc-triage .claude/skills/
```

Then in Claude Code, `/soc-triage ~<case id>`. The checkpoint produces the same three-section verdict your own skill would.

## What the skill reads

| Source | Where | Credential |
|--------|-------|-----------|
| The case and its observables | `http://localhost:9000/api/v1` | `THEHIVE_N8N_APIKEY` as a Bearer token |
| Wazuh events | `https://localhost:9200/wazuh-alerts-*/_search` | HTTP Basic `admin` / `brucon2026`, self-signed cert so `curl -k` |
| IP reputation | `https://api.abuseipdb.com/api/v2/check` | `OSINT_API_KEY`; when unset, the offline list `lab/threat-intel/malicious-ips.txt`, labelled as such |

## Screenshots

Captured from the running lab; capture commands are in `lab/exercises/README.md`.

| Figure | File | What it shows |
|--------|------|---------------|
| 1 | `guide/screenshots/module-1/01-panel.png` | The attack console |
| 2 | `guide/screenshots/module-1/02-thehive-case.png` | The case an attack created: title, tags and the description table |
| 3 | **TBC** | The terminal after `/soc-triage`, showing the three-section verdict |
| 4 | **TBC** | The verdict landed as a comment on the case |
