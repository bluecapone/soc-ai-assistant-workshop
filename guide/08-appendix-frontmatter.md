# Appendix: skill frontmatter

Every field Claude Code reads between the two `---` lines at the top of `SKILL.md`. All are optional. `description` is the one to always write. Source: [Claude Code docs, skills](https://code.claude.com/docs/en/skills), frontmatter reference. Boolean fields accept `true`/`false`, `yes`/`no`, `on`/`off`, `1`/`0`.

## Identity and loading

| Field | What it does |
|---|---|
| `name` | Display name and the `/name` command. Defaults to the folder name. |
| `description` | What the skill does. Claude uses it to decide when to load the skill. If missing, the first paragraph of the body is used. |
| `when_to_use` | Extra trigger context: phrases or example requests. Appended to `description` in the skill listing. Together they are cut at 1,536 characters. |
| `paths` | Glob patterns. When set, the skill loads automatically only while working on matching files. |
| `disable-model-invocation` | `true`: only a human starts it, with `/name`. Claude never picks it from a prompt, and its description leaves the context. For skills with side effects you want a person to trigger every time. Default `false`. |
| `user-invocable` | `false`: hidden from the `/` menu, Claude-only. For background knowledge. Default `true`. |

## Arguments

| Field | What it does |
|---|---|
| `argument-hint` | Hint in autocomplete, e.g. `[issue-number]` or `~<case-id>`. |
| `arguments` | Named positional arguments for `$name` substitution in the body. Space-separated string or YAML list. |

The body also sees `$ARGUMENTS` (everything after the command) and `${CLAUDE_SKILL_DIR}` (the skill's own folder), `${CLAUDE_PROJECT_DIR}` (the folder Claude Code was started from).

## Tools and permissions

| Field | What it does |
|---|---|
| `allowed-tools` | Tools Claude may use without asking, for the turn that invoked the skill. Space- or comma-separated, or a YAML list. `Bash(${CLAUDE_SKILL_DIR}/scripts/x.sh *)` pre-approves one bundled script. |
| `disallowed-tools` | Tools removed while the skill is active. Cleared on your next message. |
| `hooks` | Hooks registered when the skill is invoked, kept for the rest of the session. |
| `shell` | `bash` (default) or `powershell` for inline `!command` blocks in the body. |

## Model and execution

| Field | What it does |
|---|---|
| `model` | Model override for the rest of the turn, or `inherit`. Same values as `/model`. |
| `effort` | `low`, `medium`, `high`, `xhigh`, `max`, for the turn. |
| `context` | `fork`: run the skill in a forked subagent. |
| `agent` | Subagent type, with `context: fork`. |
| `background` | With `context: fork`, `false` waits for the result in the same turn. Default `true`. |

## Accepted, not acted on

| Field | What it does |
|---|---|
| `metadata` | Free YAML map for your own tooling (author, version, tags). |
| `license` | License, from the Agent Skills spec. |
| `compatibility` | Environment requirements, up to 500 characters, from the Agent Skills spec. |

## Portable subset

The [Agent Skills](https://agentskills.io) open spec, which other agents implement, defines `name`, `description`, `license`, `allowed-tools`, `compatibility` and `metadata`. The rest of the table is Claude Code only. A skill meant to travel keeps its trigger phrases inside `description`, since `when_to_use` does not exist elsewhere.

## Rules

- The opening `---` must be line 1 of the file, or the whole file is treated as body.
- No angle brackets (`<`, `>`) in the frontmatter.
- Folder in kebab-case, `SKILL.md` spelled exactly so.
- No `README.md` inside the skill folder. Human documentation goes next to it.
