# Part 3: let it decide

## What changes here

Module 3 widens the scope in two ways.

First, the agent sees the whole case instead of one observable: every finding attached to it, every earlier report, everything the attendee has gathered so far.

Second, the agent decides which tools to call and when. The workflow no longer forces every lookup to run; the agent reasons about which sources matter for this alert and queries only those.

## Case scope, not observable scope

The agent reasons across everything attached to the case. This is why Module 2's step of narrowing your input is gone: the point is now exactly the opposite. Feed the entire case payload (every observable, every earlier report from the attendee's work) so the agent can assess the full picture before deciding what to investigate further.

## Now it chooses

Module 2 fixed the lookup sequence: each HTTP Request node ran in order, every time. Module 3 inverts this. The agent sees the HTTP Request nodes as tools it can call, and it decides which ones matter for this case.

On each turn, the agent reasons about the evidence, decides if it needs more information, and chooses which tool to invoke. The tool call is a turn. The iteration cap limits how many turns the agent takes. The Tools Agent's Max Iterations option defaults to 10 turns.

The cap is a safety limit. In normal triage the agent finishes in two or three turns. If a run ever reaches ten, it ends without a verdict and the execution stops in the trace. That almost always means a tool kept failing and the agent kept retrying, so read the tool calls to see what went wrong.

## Same contract, third time

Three modules, three different workers, one output shape. Every case (whether it came through Module 1's manual review, Module 2's automatic run, or Module 3's agent loop) carries the same three sections: a summary of what the alert means, a suggested close state (true positive, false positive, true positive but not malicious, or other), and recommended actions. This consistency lets attendees compare all three approaches side by side at the end.

## The difference between recommending and acting

A model that recommends is not a model that acts. The difference is one line in a configuration file: a permission and a credential. Not a smarter model, not a better prompt, not a bigger context. The model alone cannot touch the range; without the write credential to the system of record, no recommendation becomes an action. This is the workshop's central claim. Say it slowly.

## What we did not give it

The agent has no write permission to the range. It cannot trigger containment, and it has no path to the wider system of record. The one narrow exception is TheHive: like Module 1 and Module 2, it writes its recommendation there, and nothing beyond that. Writing a recommendation is not the same as acting on it; nothing closes, escalates, or contains until you decide, in Step 9.

## You are the gate

The agent recommends. The attendee decides. Every verdict that comes from this workflow waits for a human before anything happens to it.

A real gate requires three things:

1. The reviewer must have the authority to overrule the machine. If the gate is staffed by someone with no power to disagree, it is an approval ritual, not a gate.
2. The surface must show the evidence so the reviewer can read why the agent recommended this verdict.
3. The two choices (agree or disagree) must be equally easy and neither one the default.

## One workflow on the webhook at a time

The `thehive-alert` path can feed only one active workflow. n8n refuses to activate a second workflow on the same path. If you build Module 3 as a new workflow, **deactivate your Module 2 workflow first**, or the activation fails and cases keep going to the old chain.

## Step 1: swap the chain for an agent

In the n8n workflow, replace the Basic LLM Chain node with an AI Agent node. The shape stays the same; the behavior changes. The chain received all your enrichment data at once and returned one answer. The agent can loop and call tools to gather what it needs.

## Step 2: feed it the whole case

Fetch the case from TheHive.

```
GET http://thehive.localhost/api/v1/case/{caseId}
Authorization: Bearer <your TheHive API key>
```

The case record includes the title, description, tags, and status (the narrative). Observables are attached separately and require the query shown next. Feed the case payload to the agent node as the input context.

To fetch the observables themselves (separate from the case):

```
POST http://thehive.localhost/api/v1/query
Authorization: Bearer <your TheHive API key>
Content-Type: application/json

{
  "query": [
    { "_name": "getCase", "idOrName": "<caseId>" },
    { "_name": "observables" }
  ]
}
```

Do not include write credentials to the range or containment credentials. The agent needs read-only access to enrichment sources; that is sufficient.

## Step 3: connect your lookups as tools

The HTTP Request nodes you built in Module 2 (the Wazuh lookup, AbuseIPDB, and the two VirusTotal lookups) become tools the agent can invoke. You no longer control when they run. The agent reads the case, decides which tools will help, and calls them in the order it chooses.

Add two more tools while you are here:

- *ThreatFox* (abuse.ch): one lookup that takes any indicator (an IP, a domain, a URL, or a hash) and says whether it is known malware or C2. It uses the `ABUSECH_AUTH_KEY` the lab already holds.
- *Related cases*: a TheHive query that lists other cases tagged with the same attacker IP. It lets the agent check whether the address has shown up before, which is often what settles a verdict.

Give each tool a name and a one-line description. The agent picks a tool by its description, so write the description for the agent to read.

## Step 4: move to the frontier tier

Change the model on the AI Agent node from the standard tier to claude-sonnet-5. This model can hold a plan across multiple turns; it can call a tool, read the result, reason about it, and decide what to ask next. The standard tier cannot maintain this chain of thought reliably across tool calls.

The live model id is announced from the slide on the day.

**Set the model's max output tokens.** The model node has a per-turn token limit. Leave it at the low default and the model gets cut off mid-turn: it never finishes a thought, keeps looping until it hits the iteration cap, and writes a blank verdict. There is no error, so the failure is easy to miss. Set the max tokens to <ins>4096</ins> so the agent has room to reason and answer.

## Step 5: extend the prompt

The agent needs three additions to its system prompt:

1. **Give it permission.** "You may use these tools to investigate the case and gather evidence." This signals that tool calling is the intended mode.
2. **Constrain the verdict.** "Your recommended close state must be one of: true positive, false positive, true positive but not malicious, or other. Only recommend CLOSE if the evidence strongly supports it; if uncertain, recommend other and explain your reasoning."
3. **Name the tools.** List each tool and when to use it, so the agent knows that ThreatFox exists and that related cases pivots on the attacker IP. The agent only calls a tool it can name.

These three additions guide the agent without removing its reasoning.

## Step 6: extend the schema

The output parser that receives the agent's response now holds two fields alongside the narrative. It must capture a determination ("This alert is malicious because..." or "This alert is benign because...") and pair that with a suggested close state. The agent no longer just tells a story; it tells a story and makes a judgment.

## Step 7: fire an alert

Use the browser at http://panel.localhost to fire a test alert into the lab. The same panel you used in Module 1 and Module 2 works here.

**One trigger per case.** The workflow runs when a case is created, and the lab groups alerts from the same attacker IP into one case for 15 minutes. So firing the same attack twice inside that window adds to the open case, and the workflow does not run a second time. To get a fresh run: wait 15 minutes, pick a different attacker IP in the fire dialog, or fire a different attack.

## Step 8: watch what it decided to look up

Let the workflow run to completion. When it finishes, open the n8n execution trace and read the flow. The agent called some tools and skipped others. The trace shows which ones and in which order.

Read the agent's reasoning: why did it call a Wazuh lookup and skip the email log lookup? This is where you see the agent thinking. Tool-calling through the gateway's base-URL override can fail silently rather than loudly. If the trace shows zero tool calls, check your configuration before assuming the agent chose not to look anything up.

Two more failures look like the agent misbehaving but are really wiring. If the verdict comes back blank and the trace shows the agent ran the full iteration cap, the model's max output tokens is too low (see Step 4). If the case gets several copies of the verdict, the workflow handed the agent more than one item: the observable lookup returns one item per observable, so the agent ran once per observable. Collapse them to a single item before the agent. The checkpoint does this with <ins>Execute Once</ins> on the node that assembles the case.

## Step 9: approve or reject

Go to TheHive and open the case. You are the gate. You can agree with the agent's recommendation, or you can disagree and explain your reasoning. Write your choice in the case timeline. Nothing moves (no close, no escalation, no containment) until you decide.

## Step 10: put the three side by side

Put the three cases side by side. You have a Module 1 case from the manual review, a Module 2 case from the automated run, and a Module 3 case from the agent loop. All three carry the same three-section verdict shape (summary, suggested close state, recommended actions), but the worker and the reasoning path differ. Compare them side by side to see what changed across the three approaches.

## Stuck five minutes?

Open n8n, find the workflow `SOC triage, Module 3 checkpoint (AI Agent)`, deactivate whatever workflow is currently active on the `thehive-alert` webhook path (there can be only one), then activate the checkpoint. Fire an alert and resume from Step 8.
