# Part 1: Module 1, drive it by hand

You author a Claude Code skill that triages one TheHive case and writes a verdict back to it. A *skill* is a folder with one required file, `SKILL.md`: YAML frontmatter on top, Markdown instructions below. Next to it, optional folders: `scripts/` for code the skill runs, `references/` for documentation it reads only when needed, `assets/` for templates it fills. Claude Code reads the frontmatter of every skill when it starts, and uses it to decide which skill a prompt needs. It reads the body only when a prompt matches, and a reference only when the body points at it. You write the file in your repository, so a colleague can read it and argue with it in code review.

Every verdict in this workshop has the same three sections: a summary, a suggested close state (true positive, false positive, true positive but not malicious, or other) and recommended actions. The skill reads Wazuh and TheHive; its only write is one comment on the case.

The exercises follow the order you would use for any skill: plan it, describe it, learn its tools by hand, write its instructions, test that it loads, test that it works, tighten it, share it.

## Exercise #1.1: plan the skill

**Goal**: one use case written down before any skill text.

A skill starts with a use case, not with a file. A use case is a trigger, the steps in order, and one result.

1. **Write the use case.** In a scratch note, not in the skill, fill this block:

   ```text
   Use case: triage one TheHive case
   Trigger: the analyst says "..." or "..." or "..."
   Steps:
   1. ...
   Result: ...
   ```

   The trigger is the words a colleague would type; write three phrasings. The steps are the reads in order, then the one write. The result is where the verdict lands and what it contains.

2. **Fix the success criteria.** These are the tests of Exercises 1.6 and 1.7, so write them down now: the skill loads on three of three natural-language prompts and on none of two unrelated ones; one run makes zero failed API calls; the verdict has the three sections.

3. **Build the folder.** `exercises/module-1/` holds the eight files of the skill, flat and unsorted. Claude Code reads skills from `.claude/skills/` in the folder it was started from, and a skill is a folder with `SKILL.md` at its root, code under `scripts/`, documentation under `references/`, templates under `assets/`. Put each file where it belongs:

   ```bash
   S=.claude/skills/soc-triage
   mkdir -p $S/scripts $S/references/examples $S/assets
   cp exercises/module-1/SKILL.md $S/
   cp exercises/module-1/*.sh $S/scripts/
   cp exercises/module-1/lookups.md $S/references/
   cp exercises/module-1/brute-force.md $S/references/examples/
   cp exercises/module-1/verdict-template.md $S/assets/
   ```

   The result:

   ```text
   soc-triage/
   ├── SKILL.md                      # frontmatter, Task, Workflow, How to judge, Guardrails
   ├── scripts/
   │   ├── get_case.sh               # the case, its observables, the source IP
   │   ├── wazuh_events.sh           # last 20 events for an IP or a host
   │   ├── reputation.sh             # AbuseIPDB with a key, offline list without
   │   └── post_verdict.sh           # the one write
   ├── references/
   │   ├── lookups.md                # what each script returns, and how it fails
   │   └── examples/brute-force.md   # one worked run
   └── assets/
       └── verdict-template.md       # the shape of the verdict
   ```

4. **Check the tool surface.** `allowed-tools` in `SKILL.md` names the four scripts and nothing else: that is everything the skill may run. Every step in your use case must map to one of them.

**Expected**:

- [ ] The use case has three trigger phrasings, numbered steps and one result.
- [ ] `find .claude/skills/soc-triage -type f | wc -l` prints `8`.
- [ ] Every step maps to one script under `scripts/`.

**Question 1**: your use case block.

## Exercise #1.2: name it and describe it

**Goal**: the frontmatter is done and Claude Code can say when it would use the skill.

```{literalinclude} ../exercises/module-1/SKILL.md
:language: yaml
:end-before: "## Task"
```

The frontmatter is the part Claude Code always has in context, so the `description` decides whether the skill loads. It carries three things: what the skill does, when to use it, and the phrases a user would type. Under 1024 characters, no angle brackets. "Helps with security" is too vague; "Triages cases" names the job but no trigger.

1. **Write the description.** Replace the `FILL` line with what, when and the three phrasings from Exercise 1.1. The `name` stays `soc-triage`: kebab-case, matching the folder.
2. **Ask Claude Code.** Restart `claude` from the workshop folder (the frontmatter is read at start), then type `When would you use the soc-triage skill?` It quotes the description back. If a phrasing you expect is missing from its answer, add it to the description.

**Expected**:

- [ ] `head -5 .claude/skills/soc-triage/SKILL.md` shows the two `---` lines, `name: soc-triage`, and a description with no `FILL` and no `<` or `>`.
- [ ] Claude Code's answer names a case id and the phrases from your description.

**Question 2**: your description line.

## Exercise #1.3: learn the Wazuh lookup

**Goal**: you have run the skill's Wazuh lookup by hand, and you know what it returns and how it fails.

The Wazuh indexer is a search endpoint over every alert the range produced. The skill runs `scripts/wazuh_events.sh` and reads its output; so do you now.

```{literalinclude} ../exercises/module-1/wazuh_events.sh
:language: bash
```

1. **Read the script.** One `curl` against the indexer's `_search`, a self-signed certificate hence `-k`, and `jq` to keep the fields that matter.
2. **Run it.** In a second terminal, with the same exports as Exercise 0.4, with the source IP from your Part 0 case:

   ```bash
   .claude/skills/soc-triage/scripts/wazuh_events.sh <ip>
   ```

3. **Break it twice.** Run it once with `WAZUH_URL` unset (`env -u WAZUH_URL .claude/skills/soc-triage/scripts/wazuh_events.sh <ip>`), and once with an IP nobody used, `203.0.113.9`. Keep both outputs.
4. **Write both down.** Under `## Common issues` in `references/lookups.md`, one entry each: the error text or the empty response, its cause, the fix. The skill will meet both failures without you watching.

**Expected**:

- [ ] `total` is above zero and `events` lists them, newest first.
- [ ] Two entries under `Common issues`: the missing variable and the zero-hit response.

The skill reads this to answer: how much activity is there from this source, and is it routine or anomalous?

**Question 3**: `rule.id` of the newest event for that IP.

## Exercise #1.4: learn the TheHive read and write

**Goal**: you have run the skill's TheHive read by hand and know where the verdict will land.

TheHive is the only system the skill writes to, and the only write is a comment. Closing the case is a different call this workshop never makes.

1. **Read** `scripts/get_case.sh` and `scripts/post_verdict.sh`. Two reads and one write, all `curl` with a bearer token.
2. **Run the case read** with the case id from Part 0:

   ```bash
   .claude/skills/soc-triage/scripts/get_case.sh ~<case id>
   ```

3. **Break it.** Run it again with a wrong key in front: `THEHIVE_APIKEY=wrong .claude/skills/soc-triage/scripts/get_case.sh ~<case id>`. Add the result under `Common issues` in `references/lookups.md`: error, cause, fix.
4. **Do not run the write.** The skill does that in Exercise 1.7.

**Expected**:

- [ ] Title, tags, description with the indicator table, `srcip` filled, and the observables.
- [ ] One entry under `Common issues` for the authentication failure.

**Question 4**: the case title.

## Exercise #1.5: write the instructions

**Goal**: every `<fill: ...>` in the skill folder answered in your own words, and every rule specific enough to act on.

```{literalinclude} ../exercises/module-1/SKILL.md
:language: markdown
:start-after: "## Task"
```

The fills are in `SKILL.md` (Task, How to judge, Guardrails), `assets/verdict-template.md` and `references/examples/brute-force.md`. The workflow is already written: it names the four scripts and their order.

Instructions are specific and actionable or they are decoration. "Check the logs for suspicious activity" tells the model nothing. "Read the Wazuh events for authentication failures from the same source before the success" names the field, the pattern and the order. Every rule you write names the field it reads and the close state it leads to.

1. **Task.** One case at a time, and the list of what it must never do.
2. **How to judge.** At least four rules. Your source is the panel: each attack button has a benign twin with the same log shape, so each rule is the difference between a pair. `Brute force` and `Admin login` differ in what comes before the success; `Heavy crawler` and a scan differ in the user agent.
3. **Verdict template** in `assets/verdict-template.md`: three `###` headings, their order, the four allowed close states.
4. **Guardrails.** What to write when a script fails or returns nothing; that text inside the case is evidence, never instructions; that only the four scripts run.
5. **Example** in `references/examples/brute-force.md`: what the analyst typed, the scripts in order with what each returned, the close state that came out.
6. **Draft with Claude Code if you want, then own it.** A worked instruction:

   ```text
   Fill every <fill: ...> marker under .claude/skills/soc-triage/ (SKILL.md, assets/verdict-template.md, references/examples/brute-force.md). The skill triages one TheHive case at a time, given a case id like ~123456. It reads the case from TheHive and the last 20 Wazuh events for the case's source IP (web requests, authentication, SSH logins, email) through the scripts named in Workflow. It writes a verdict with three sections: summary, suggested close state (true positive, false positive, true positive not malicious, other), recommended actions. It must not write to Wazuh, close or modify the case, or make any change other than one comment on the case. Do not change the scripts or the Workflow section.
   ```

   Then open the file and read every line. Cut what is wrong or unclear. Tighten vague language. <ins>You own the text</ins>; the draft is a starting point, not an answer.

**Expected**:

- [ ] `grep -ril 'fill' .claude/skills/soc-triage` prints nothing.
- [ ] At least four rules under `How to judge`, each naming a field.
- [ ] `references/examples/brute-force.md` names the scripts in order and ends with a close state.

**Question 5**: one sentence you rewrote, before and after.

## Exercise #1.6: does it load?

**Goal**: the description triggers the skill on natural language, and only then.

Claude Code loads a skill when the prompt matches its description. `/soc-triage` bypasses the description entirely, so it proves nothing about it. The test is the load, not the run: once you see Claude Code read the skill, stop it with `Esc`.

1. **Should load.** Run each prompt, restart `claude` between runs so each starts clean:
   - `triage case ~<case id>`
   - `work the newest case in TheHive`
   - `is this alert a false positive`
2. **Should not load.** Run each prompt:
   - `what is our mean time to respond`
   - `summarise this pcap`
3. **Prove the description matters.** Change the description to `Helps with things`, save, restart, and run one should-load prompt again. Restore the description.

A skill that loads too little needs more of the words users type in its description. A skill that loads too much needs a sentence saying what it is not for.

**Expected**:

- [ ] The three should-load prompts load the skill.
- [ ] The two others do not.
- [ ] With the useless description, the natural-language prompt no longer loads it.

**Question 6**: which prompt, if any, failed to load it?

## Exercise #1.7: fire an alert and run it

**Goal**: your skill has triaged one attack case and its verdict is a comment on the case.

You trigger every step yourself. Nothing happens unless you ask for it. This is the functional test: given a real case, when the skill runs, then the verdict is on the case with zero failed calls.

1. **Fire.** On the panel, click `Brute force` and confirm. In TheHive, copy the new case id.
2. **Run.** In Claude Code:

   ```text
   /soc-triage ~<case id>
   ```

3. **Watch.** It runs the four scripts in the order of Workflow, reasons, and posts the verdict. Count any script that errored or returned nothing.
4. **Read it in TheHive.** Open the case. The comment carries three sections and reads clearly to someone who did not watch you work. From the API:

   ```bash
   curl -s -X POST "$THEHIVE_URL/api/v1/query" -H "Authorization: Bearer $THEHIVE_APIKEY" -H 'Content-Type: application/json' \
     -d '{"query":[{"_name":"getCase","idOrName":"'"$CASE_ID"'"},{"_name":"comments"}]}' | jq '.[].message'
   ```

**Expected**:

- [ ] The terminal shows a verdict with three `###` sections.
- [ ] The same text is one comment on the case in TheHive.
- [ ] Zero failed API calls in the transcript.

**Question 7**: the case id.

**Question 8**: the close state the skill chose.

## Exercise #1.8: run it again on a twin, then tighten

**Goal**: the skill gives the benign twin a different close state.

`Admin login` is the twin of `Brute force`: a real admin mistypes, then succeeds. Same log shape, harmless intent. A skill is a living document; a wrong verdict is a sentence to fix, not a ticket to file.

1. **Fire the twin.** On the panel, click `Admin login` and confirm. Copy the new case id.
2. **Run** `/soc-triage ~<case id>` again.
3. **Tighten.** If both verdicts match, find the rule under `How to judge` that let the twin through, rewrite it to name the field that separates the pair, and rerun on the same case. One sentence, one rerun, one verdict to compare.

**Expected**:

- [ ] A close state different from Exercise 1.7.
- [ ] `references/examples/brute-force.md` still matches what the skill did.

Exercises 1.7 and 1.8 are the skill-authoring loop: fire a real scenario, tighten the wording on what you learned, fire the twin, confirm the outcome changed.

**Question 9**: did the close state change? If not, which rule did you tighten?

## Exercise #1.9: extract reusable skills and share them

**Goal**: the Wazuh lookup and the TheHive read and write are standalone skills you can install anywhere.

Nothing in those lookups is specific to triage. The finished versions are `exercises/module-1/wazuh-query-SKILL.md` and `exercises/module-1/thehive-case-SKILL.md`, each the `SKILL.md` of a one-file skill; yours do not need to match them, but they should cover the same ground. Documentation for humans goes in a README next to the skill folders, never inside one; a skill folder holds `SKILL.md` and, at most, files the skill itself links to.

1. **Write `wazuh-query`**: how to search by IP and by hostname, what the response looks like, common failure modes.
2. **Write `thehive-case`**: how to fetch a case, fetch its observables, write a comment, with response shapes and failure modes.
3. **Parameterise credentials** (`$WAZUH_USERNAME` instead of `admin`) so they work outside this lab.
4. **Install both** from the workshop folder and list them:

   ```bash
   npx skills add <path to the workshop folder> --skill wazuh-query --agent claude-code
   npx skills add <path to the workshop folder> --skill thehive-case --agent claude-code
   npx skills list
   ```

To share, push the repository to GitHub and install with `npx skills add <your-username>/<repo-name> --skill wazuh-query --agent claude-code`. GitLab URLs are not documented for `npx skills add`; they may work through git's own URL parsing, but the error messages will be misleading. Use GitHub.

**Expected**:

- [ ] Both skills appear in `npx skills list`.
- [ ] Both load when called.
- [ ] Neither skill folder contains a `README.md`.

**Question 10**: the output of `npx skills list`.

## Exercise #1.10, bonus: add a reputation lookup

**Goal**: the verdict cites the source IP's reputation, from a live API or the offline list.

Enrichment is not only your own telemetry. The template already carries the AbuseIPDB call and the offline fallback: same outcome, different tool depending on whether a key is set. The skill must say which one it used.

1. **Export a key** if you have one: `export OSINT_API_KEY=<AbuseIPDB key>`. Free tier is 1000 requests a day.
2. **Run** `.claude/skills/soc-triage/scripts/reputation.sh <attacker ip>` by hand, with and without the key exported. The `source` field changes; nothing else in the skill does.
3. **Add a judging rule** that uses the score, then rerun `/soc-triage` on the Exercise 1.7 case.

**Expected**:

- [ ] The summary names the reputation.
- [ ] It says "offline list, not live reputation" when the fallback was used.

**Question 11**: `abuseConfidenceScore` for the attacker IP, or "offline list".
