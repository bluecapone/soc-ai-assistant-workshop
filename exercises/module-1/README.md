# Module 1 files

The reference files Module 1 reads, flat. Exercise 1.1 says where each one goes.

- `SKILL.md`, `lookups.md`, `brute-force.md`, `verdict-template.md`: four of the eight files of the `soc-triage` skill you build.
- The four `.sh` scripts are not here. Exercise 1.2 generates them from the docs, which is the exercise. An instructor hands them over if the docs are out of reach.

## Security

Skills execute shell commands and API calls. Review the skill files before installing, especially if they come from a source you do not fully trust. These skills contain only `curl` and `jq` commands. The environment variables you export (usernames, passwords, API keys) reach only the hosts named in those commands.
