# Module 1 files

Everything Module 1 needs, flat. Exercise 1.1 says where each file goes.

- `SKILL.md`, `get_case.sh`, `wazuh_events.sh`, `reputation.sh`, `post_verdict.sh`, `lookups.md`, `brute-force.md`, `verdict-template.md`: the eight files of the `soc-triage` skill you build. Exercise 1.2 generates the four `.sh` files from the docs. These copies are the fallback when the docs are out of reach.

## Security

Skills execute shell commands and API calls. Review the skill files before installing, especially if they come from a source you do not fully trust. These skills contain only `curl` and `jq` commands. The environment variables you export (usernames, passwords, API keys) reach only the hosts named in those commands.
