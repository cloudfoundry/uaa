# Using AI Agents with UAA

This document explains how AI coding agents are configured in this repository and how to
work effectively with them.

## How It Works

All agent rules and reusable skill patterns live in a single place:

```text
ai/
  rules/       <- coding conventions loaded by all agents
  skills/      <- reusable task patterns (add here as identified)
  plans/       <- ephemeral working notes (gitignored)
```

Three thin entry-point files point every supported agent at `ai/rules/`:

| File | Agent |
| --- | --- |
| `AGENTS.md` | OpenAI Codex, Gemini CLI, and any AGENTS.md-compatible agent |
| `CLAUDE.md` | Claude Code |
| `.github/copilot-instructions.md` | GitHub Copilot (VS Code, JetBrains, agent mode) |

Cursor is wired via `.cursor/rules → ai/rules` and `.cursor/skills → ai/skills` symlinks
created by `scripts/setup_cursor.sh`.

## First-Time Setup

After cloning, run once to wire Cursor:

```bash
./scripts/setup_cursor.sh
```

## Current Rules

| Rule file | Applies when | What it enforces |
| --- | --- | --- |
| [`markdownlint.mdc`](rules/markdownlint.mdc) | Editing any `.md` or `.mdc` file | Run `npx markdownlint-cli2 --fix <file>` after every edit |
| [`documentation.mdc`](rules/documentation.mdc) | Any code change | Keep `docs/`, config reference, and API docs in sync |
| [`java-testing.mdc`](rules/java-testing.mdc) | `*Test*.java`, `*IT.java` | AssertJ, Awaitility, `@ParameterizedTest`, `@Nested` |
| [`shellcheck.mdc`](rules/shellcheck.mdc) | `**/*.sh` | Run `shellcheck <file>` after every shell script edit |
| [`ai-instructions.mdc`](rules/ai-instructions.mdc) | Changing `ai/rules/` | Keep `AGENTS.md`, `CLAUDE.md`, and `copilot-instructions.md` in sync |

## Working Plans

Agents may write task plans to `ai/plans/` before implementing. These files are gitignored
and are never committed — they are ephemeral working notes only.
``
If you want to preserve a significant architectural decision, write an ADR in `docs/adrs` instead.
``

## Adding a New Shared Rule

1. Create `ai/rules/your-rule.mdc` with the appropriate frontmatter:

   ```yaml
   ---
   description: "One-line summary"
   globs: "optional/glob/pattern"
   alwaysApply: false
   ---
   ```

2. Write the rule content in Markdown below the frontmatter.
3. Run `npx markdownlint-cli2 --fix ai/rules/your-rule.mdc`.
4. Re-run `./scripts/setup_cursor.sh` to create the symlink in `.cursor/rules/`.
5. Update the summary table in `AGENTS.md`, `CLAUDE.md`, and
   `.github/copilot-instructions.md` (see `ai-instructions.mdc`).

## Personal Rules (not committed to the repo)

You can add your own rules that apply only to your local checkout without modifying any
committed file.

### Cursor

After running `./scripts/setup_cursor.sh`, place personal `.mdc` files directly in
`.cursor/rules/`. The setup script only creates and manages symlinks for files in
`ai/rules/`; any real files you place there are left untouched and are gitignored.

```bash
# Example: create a personal rule
cat > .cursor/rules/my-personal-style.mdc << 'EOF'
---
description: "My personal preferences"
alwaysApply: true
---
# My Preferences
Always use British English spelling in comments.
EOF
```

Re-running `./scripts/setup_cursor.sh` will not remove or overwrite this file.

### Claude Code

Claude Code also reads `CLAUDE.md` files in subdirectories, and reads a global user-level
file at `~/.claude/CLAUDE.md`. Add personal instructions there — they apply across all
your repos and are never committed.

### GitHub Copilot

Copilot only reads `.github/copilot-instructions.md` and has no per-user override
mechanism at the repository level. Personal preferences for Copilot must be configured
via VS Code / JetBrains user settings.

## Adding a New Skill

Skills are reusable step-by-step patterns for common tasks (e.g. "how to add a new config
property end-to-end"). Add `.mdc` files to `ai/skills/` following the same frontmatter
convention as rules.

## About `.github/copilot-instructions.md`

This file is the standard GitHub Copilot configuration mechanism for repository-level
instructions. GitHub Copilot reads it automatically whenever it operates inside this
repository — there is nothing to configure.

- **Location:** `.github/` is GitHub's conventional directory for repository configuration
  (alongside `CODEOWNERS`, `PULL_REQUEST_TEMPLATE.md`, and `workflows/`). Placing it there
  keeps the repo root clean and follows GitHub's own convention.
- **Used by:** GitHub Copilot Chat (VS Code, JetBrains, GitHub.com), Copilot code completions
  context, and GitHub Copilot coding agent (agentic / autonomous mode).
- **Content:** Keep it brief — Copilot embeds this as context on every prompt, so long
  instructions increase token usage. The file should point to `ai/rules/` rather than
  reproducing rule content inline.
