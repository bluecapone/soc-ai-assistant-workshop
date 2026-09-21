# Example: Brute force

The analyst typed `/soc-triage ~123456` (or "triage case ~123456").

1. `get_case.sh ~123456` returned title `Brute force login from 198.51.100.7`, tags `rule:100210`, `srcip` `198.51.100.7`.
2. `wazuh_events.sh 198.51.100.7` returned 12 events: eleven authentication failures for `data.dstuser` `admin` inside two minutes, then one success.
3. `reputation.sh 198.51.100.7` returned `{"source":"offline list, not live reputation","listed":true}`.
4. Rule 2 applies: failures before the success from the same source, and a listed IP.
5. Verdict posted with `post_verdict.sh ~123456`. Close state: `true positive`.
