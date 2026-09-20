# Module 2: run it unattended

## What changes here

Your focus shifts from running the workflow by hand to letting it run automatically. The trigger moves from your button press to a webhook fired by your alert system. The work happens without your intervention. The reasoning itself does not change. It is the same three-section contract, built the same way you built it in Module 1.

## This was version one

The Five9 SOC ran its first version about two years ago. It used a cheap model, made a single call to get an answer, and did not loop or choose between tools. It worked. This module reproduces that architecture.

## What it costs per alert

> **TBC.** Figure pending employer disclosure review (G6).

## Basic LLM Chain, not AI Agent

| | Basic LLM Chain | AI Agent |
|---|---|---|
| Calls to the model | One (single-pass) | Loops until it decides |
| Chooses which tool to call | No | Yes |
| What happens each turn | The model sees all your enrichment data at once and writes a verdict directly | The model sees the question, decides which source to query, calls a tool, reads the result, and repeats |
| Used in | Module 2 (this module holds the loop back on purpose) | Module 3 |

## Same contract as Module 1

The workflow writes the same three sections that your Module 1 skill wrote: a narrative summary, a suggested close state for the case, and recommended actions. The worker changed (from you to the model), but the output shape did not.

## When it is wrong, you fix the text

When a verdict is wrong, you do not retrain, tune, or file a ticket to a vendor. You read the bad line in the verdict, open the system prompt in your workflow, change a sentence, and run the same alert through again. That edit becomes the fix.

An analyst reads a verdict that is wrong and improves the skill's system prompt text directly. This feedback loop is the real one that the Reference Framework names as its component 13.

The concrete path runs like this:

1. Read the wrong verdict.
2. Edit the system prompt text (the skill's `.md` file).
3. Re-run the workflow on the same alert.
4. Confirm the new verdict is right.
5. Push the prompt change to the shared repo so a teammate can read it, disagree with the logic, and send it back with improvements.

## Step 1: open the skeleton

The workflow skeleton is pre-built: a webhook trigger at one end and an HTTP node writing the verdict back to TheHive at the other. Everything between them is yours to build. Start here and wire your enrichment and reasoning nodes into that skeleton.

### Filter before you extract

TheHive's webhook notifier fires on every case and alert event, with no event-type restriction configured on the TheHive side. Your own workflow's last step updates the case (writing the verdict), which is itself an event the notifier will forward back to this same webhook. Without a filter, the workflow re-triggers itself in a loop.

Add a Filter or IF node immediately after the Webhook trigger, before the `Extract case` node. Keep only creation events; drop update events.

Configure the filter: keep rows where `{{ $json.body.objectType }}` equals `Case` AND `{{ $json.body.action }}` equals `create`. Update events carry `action: "update"` instead and will be dropped, preventing the workflow from re-triggering itself when it writes the verdict back to TheHive.

## Step 2: extract the fields

TheHive sends a Case creation event in the webhook payload. The payload contains the case record with fields like title and description; observables are attached to the case after creation and do not arrive in this webhook payload. The case's description field contains structured text with indicators formatted as markdown tables. Extract these indicators from the description text using regex.

Here is the exact format the regexes expect:

```text
| Source IP | `192.0.2.1` |
| Target | `10.0.0.5` |
on host `web-server-01`
```


Use a Set node to pull the fields you need out of the webhook's payload. Add a field for each item in the table below. Reference them with the expressions shown. TheHive's case object nests under `object` in the payload, and each expression includes a fallback using `||` for when the field is absent.

| Field | Expression |
|---|---|
| `caseId` | `{{ $json.body.object._id \|\| $json.body.objectId \|\| '' }}` |
| `title` | `{{ $json.body.object.title \|\| 'unknown case' }}` |
| `ruleId` | `{{ ((($json.body.object.tags \|\| []).find(t => String(t).startsWith('rule:'))) \|\| 'rule:').slice(5) }}` |
| `srcip` | `{{ (String($json.body.object.description \|\| '').match(/\\\| Source IP \\\| \`([^\`]+)\` \\\|/) \|\| [])[1] \|\| '' }}` |
| `host` | `{{ (String($json.body.object.description \|\| '').match(/on host \`([^\`]+)\`/) \|\| [])[1] \|\| '' }}` |
| `target` | `{{ (String($json.body.object.description \|\| '').match(/\\\| Target \\\| \`([^\`]+)\` \\\|/) \|\| [])[1] \|\| '' }}` |
| `domain` | `{{ (String($json.body.object.description \|\| '').match(/host=([A-Za-z0-9.-]+\.[A-Za-z]{2,})/) \|\| [])[1] \|\| '' }}` |
| `tagsForModel` | `{{ ($json.body.object.tags \|\| []).filter(t => !String(t).startsWith('kind:')) }}` |
| `descriptionForModel` | `{{ String($json.body.object.description \|\| '').split('\\n').filter(l => !l.startsWith('\\| Classification \\|')).join('\\n') }}` |

The `tagsForModel` and `descriptionForModel` fields exist separately from `tags` and `description` because the model must not see the analyst's own verdict tags (those starting with `kind:`) or the classification row they added to the description; passing these would let the model parrot back the answer already on the case.

The payload TheHive actually sends is the single most likely thing to differ from what these expressions assume. Pin the webhook, fire a test alert, and inspect that execution's actual input in n8n. Correct the expression paths against what you see. This is normal work, not a sign something is broken.

If a field extraction returns nothing, it returns an empty string instead of failing. Every node downstream runs anyway. The model will write a narrative about an alert with a missing field (like no source IP), and it will do so with confidence. You will only notice the omission by reading the output.

Test this node to confirm every field you expect actually arrives.

## Step 3: add the Wazuh lookup

Add an HTTP Request node. Feed it from the `Extract case` Set node you built in Step 2.

Configure the node with these settings: POST method, URL `https://wazuh.indexer:9200/wazuh-alerts-*/_search`, HTTP Basic Auth with username `admin` and password `brucon2026`, JSON body. Enable the "ignore SSL issues" toggle because the Wazuh indexer uses a self-signed certificate.

```json
{
  "size": 20,
  "query": { "match": { "data.srcip": "{{ $json.srcip }}" } },
  "sort": [ { "timestamp": "desc" } ]
}
```

Test this node in isolation before wiring its output downstream. Pin the webhook, fire a test alert, and inspect this node's actual output in n8n. This verify-before-wire habit catches configuration mistakes early.

## Step 4: add the rest of your sources

Add one HTTP Request node per source: Wazuh (already done), then auth logs, SSH logs, mail logs, and proxy logs. Each one queries the same `wazuh-alerts-*` index on the same indexer and credential as Step 3. Only the match field changes: filter on the field that identifies each source's events (for example the relevant rule id, or a field specific to that log type) instead of `data.srcip`. Build them one at a time.

## Step 5: merge the results

Add a Merge node to combine the results from all your enrichment sources into a single item. The model needs to read everything at once to write the verdict. The merge collapses the multi-branch output into one payload that feeds into the model node.

## Step 6: add the model

Add a Basic LLM Chain node, then add an OpenAI Chat Model sub-node to it. For its credential, select the pre-provisioned "Model gateway" entry from the dropdown rather than creating a new one: it already has the gateway's URL and your per-attendee token configured. The node is called "OpenAI Chat Model" because that is n8n's built-in name for this node type, not because OpenAI is involved. See Connect for what is actually running behind the gateway. The model field on that sub-node accepts free-text input.

When the /models endpoint does not list a model ID you want, type the ID directly. If you see a placeholder model ID in this section, check it against the slide on the day, as the live ID is announced there.

> **TBC.** Model id: `gemini-3.5-flash-lite` (per decisions-2026-09-15.md G14), confirmed and announced live from the slide on the day.

## Step 7: paste your prompt

Paste your Module 1 system prompt into the system-message field of the LLM Chain node. Do not rewrite it. This is the port: the same reasoning path you built by hand in Module 1 now runs unattended here.

## Step 8: enforce the schema

Add a Structured Output Parser node to enforce the three-section contract. This node holds the schema with these three fields:

```json
{
  "summary": "string",
  "suggested_close_state": "one of: true positive, false positive, true positive not malicious, other",
  "recommended_actions": "string"
}
```

A weak model either fills all three sections or fails visibly. You see the error and can revise the prompt.

## Step 9: fire an alert and walk away

Trigger the workflow. Go to the panel in the lab interface and fire an alert, then do not touch anything else. The webhook fires, the workflow runs, the model writes the verdict, and the verdict is written back to TheHive. You have automated the work.

## Step 10: read what it wrote

Open the case in TheHive. Read the three sections that the model wrote: the narrative, the close state, and the recommended actions. Read it as an analyst would.

Ask yourself:

- [ ] Do these sections make sense?
- [ ] Does the narrative match what your enrichment data showed?
- [ ] Is the close state right for this alert?
- [ ] Do the actions match the narrative?

## Step 11: improve the skill

This is the heart of the block. Find the weakest line in the verdict: the one that does not match what you know about the alert. Trace that line back to a sentence in your system prompt. Change that sentence and save it. Run the same alert through the workflow again. Did your change improve the verdict? If not, revise the prompt again. Each edit is a small, testable change: one sentence, one re-run, one verdict to check.

## Step 12: compare with Module 1

Keep both cases open. You have a Module 1 case from the manual run and a Module 2 case from the automated run. You will compare them side by side at the end of the day to see what changed when the human stepped out of the loop.

## Stuck five minutes?

If you are stuck five minutes into this module, the Module 2 checkpoint is already imported and waiting in n8n (inactive). Open n8n, find the workflow `SOC triage, Module 2 checkpoint (LLM chain)`, deactivate whatever workflow is currently active on the `thehive-alert` webhook path (there can be only one), then activate the checkpoint. Fire an alert and resume from Step 10.
