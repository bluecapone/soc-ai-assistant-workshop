# Part 3: let it decide

## What changes here

Module 3 widens the scope in two ways.

First, the agent sees the whole case instead of one observable: every finding attached to it, every earlier report, everything gathered so far.

Second, the agent decides which tools to call and when. The workflow no longer forces every lookup to run. The agent reasons about which sources matter for this alert and queries only those.

## Case scope, not observable scope

The agent reasons across everything attached to the case. This is why Module 2's step of narrowing your input is gone: the point is now the opposite. The skeleton feeds the entire case payload, every observable and every earlier report, so the agent can assess the full picture before deciding what to investigate.

## Now it chooses

Module 2 fixed the lookup sequence: each HTTP Request node ran in order, every time. Module 3 inverts this. The agent sees the lookups as tools it can call, and it decides which ones matter for this case.

On each turn the agent reasons about the evidence, decides if it needs more, and chooses which tool to invoke. A tool call is a turn. The Max Iterations option caps how many turns the agent takes. It is set to 10.

The cap is a safety limit. In normal triage the agent finishes in two or three turns. If a run reaches ten it ends without a verdict and stops in the trace. That almost always means a tool kept failing and the agent kept retrying, so read the tool calls to see what went wrong.

## Same contract, third time

Three modules, three different workers, one output shape. Every case, whether it came through Module 1's manual review, Module 2's automatic run, or Module 3's agent loop, carries the same sections: a summary of what the alert means, a suggested close state (true positive, false positive, true positive but not malicious, or other), and recommended actions. This lets you compare all three approaches side by side at the end.

## The difference between recommending and acting

A model that recommends is not a model that acts. The difference is one line in a configuration file: a permission and a credential. Not a smarter model, not a better prompt, not a bigger context. The model alone cannot touch the range. Without the write credential to the system of record, no recommendation becomes an action. This is the workshop's central claim. Say it slowly.

## What we did not give it

The agent has no write permission to the range. It cannot trigger containment, and it has no path to the wider system of record. The one narrow exception is TheHive: like Module 1 and Module 2, it writes its recommendation there, and nothing beyond that. Writing a recommendation is not acting on it. Nothing closes, escalates, or contains until you decide, in Step 7.

## You are the gate

The agent recommends. You decide. Every verdict from this workflow waits for a human before anything happens to it.

A real gate requires three things:

1. The reviewer must have the authority to overrule the machine. A gate staffed by someone with no power to disagree is an approval ritual, not a gate.
2. The surface must show the evidence so the reviewer can read why the agent recommended this verdict.
3. The two choices, agree or disagree, must be equally easy and neither one the default.

## Step 1: open the agent skeleton

The Module 3 skeleton is a different workflow from Module 2. `start.sh` imported it as `SOC triage, Module 3 skeleton (AI Agent)`. Open it.

Most of it is built. Trace it left to right:

- `Webhook`, `Case created only` and `Extract case` are the same front end as Module 2.
- `Fetch case` and `Fetch observables` read the whole case and its observables back from TheHive, and `Assemble case context` collapses them into one document for the agent.
- `Triage (AI Agent)` is the worker. Its model is already the frontier tier (`claude-sonnet-5`), its max output tokens are already set to 4096 so it has room to reason across turns, and its `Structured Output Parser` already captures a determination alongside the three sections.
- `Render verdict` and `Write verdict to TheHive` post the recommendation to the case.

The agent's system prompt already names seven tools and says when to use each. Three are wired: `wazuh_events_for_ip`, `wazuh_events_for_host`, and `thehive_related_cases`. The other four are not. Your job is to add them, so the agent can actually call every tool its prompt describes.

## Step 2: read a wired tool

The three wired tools are the pattern you copy. Open `wazuh_events_for_ip`:

- It is an HTTP Request **Tool** node, connected to the agent's Tool input (not into the main flow).
- Its `toolDescription` explains, in one line, what the tool returns and when to call it. The agent picks a tool by reading this, so it is written for the agent, not for you.
- Where a normal node would take a fixed value, the tool uses `{{ $fromAI('ip', 'IPv4 address of the source to look up', 'string') }}`. The agent fills that argument in when it decides to call the tool.

Every tool you add follows this shape: a Tool node wired to the agent, a clear `toolDescription`, and a `$fromAI(...)` placeholder for the indicator.

## Step 3: get your API keys

The four tools use AbuseIPDB, VirusTotal, and ThreatFox, the same services as Module 2. If you did Module 2, `ABUSEIPDB_API_KEY`, `VT_API_KEY` and `ABUSECH_AUTH_KEY` are already in `lab/.env`. If not, create a free account on each ([abuseipdb.com](https://www.abuseipdb.com), [virustotal.com](https://www.virustotal.com), [auth.abuse.ch](https://auth.abuse.ch)), put the keys in `lab/.env`, and <ins>re-run the start script so n8n picks up the new keys</ins>.

## Step 4: add the four tools

Add each as an HTTP Request Tool node and connect it to the agent's Tool input. Use the exact tool names the prompt already refers to, and give each a `toolDescription` the agent can act on.

| Tool | Request | Header |
| ---- | ------- | ------ |
| `ip_reputation` | `GET https://api.abuseipdb.com/api/v2/check?ipAddress={{ $fromAI('ip', 'IPv4 address to check', 'string') }}&maxAgeInDays=90` | `Key: {{ $env.ABUSEIPDB_API_KEY }}` and `Accept: application/json` |
| `vt_file_report` | `GET https://www.virustotal.com/api/v3/files/{{ $fromAI('hash', 'file sha256 to look up', 'string') }}` | `x-apikey: {{ $env.VT_API_KEY }}` |
| `vt_domain_report` | `GET https://www.virustotal.com/api/v3/domains/{{ $fromAI('domain', 'domain to look up', 'string') }}` | `x-apikey: {{ $env.VT_API_KEY }}` |
| `threatfox_search` | `POST https://threatfox-api.abuse.ch/api/v1/` with JSON body `{{ JSON.stringify({ query: 'search_ioc', search_term: $fromAI('indicator', 'IP, domain, URL or hash to search', 'string'), exact_match: true }) }}` | `Auth-Key: {{ $env.ABUSECH_AUTH_KEY }}` |

Match each `toolDescription` to what the agent's prompt says the tool is for: AbuseIPDB reputation for an IP, VirusTotal detections for a file hash, VirusTotal detections for a domain, and an abuse.ch ThreatFox lookup for any indicator. The agent only calls a tool it can read a purpose for.

## Step 5: fire an alert

Activate the workflow. n8n allows only one active workflow on the `thehive-alert` path, so **deactivate your Module 2 workflow first** or the activation fails and cases keep going to the old chain.

Then use the panel at [panel.localhost](http://panel.localhost) to fire a test alert. **One trigger per case.** The lab groups alerts from the same attacker IP into one case for 15 minutes, and the workflow runs only when a case is created. To get a fresh run: wait 15 minutes, pick a different attacker IP in the fire dialog, or fire a different attack.

## Step 6: watch what it decided to look up

Let the run finish, then open the n8n execution trace and read the flow. The agent called some tools and skipped others. The trace shows which, and in which order. Read its reasoning: why did it call a Wazuh lookup and skip another? This is where you see the agent thinking.

Tool calling through the gateway can fail quietly rather than loudly. If the trace shows zero tool calls, check your tool wiring before assuming the agent chose not to look anything up.

## Step 7: approve or reject

Go to TheHive and open the case. You are the gate. Agree with the agent's recommendation, or disagree and explain your reasoning, and write your choice in the case timeline. Nothing moves, no close, no escalation, no containment, until you decide.

## Step 8: put the three side by side

You have a Module 1 case from the manual review, a Module 2 case from the automated run, and a Module 3 case from the agent loop. All three carry the same three-section verdict shape, but the worker and the reasoning path differ. Compare them to see what changed across the three approaches.

## Stuck five minutes?

Put your hand up. An instructor will give you the Module 3 checkpoint, the finished workflow `SOC triage, Module 3 checkpoint (AI Agent)`. Import it into n8n, deactivate whatever workflow is currently active on the `thehive-alert` webhook path (there can be only one), then activate the checkpoint. Fire an alert and resume from Step 6.
