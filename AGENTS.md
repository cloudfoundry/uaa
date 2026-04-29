# Agent Guidelines

This repository uses a single source of truth for AI agent rules and skills:

- **Rules:** [`ai/rules/`](ai/rules/) — coding conventions, testing practices, documentation
  requirements, and tool usage patterns.
- **Skills:** [`ai/skills/`](ai/skills/) — reusable task patterns (added here as they are identified).
- **Plans:** `ai/plans/` — ephemeral working plans written during a task; gitignored, never committed.

All agents (OpenAI Codex, Claude Code, GitHub Copilot, Cursor) should read the files in `ai/rules/` before
starting work.

## Rules summary

| File | Applies to | Summary |
| --- | --- | --- |
| [`markdownlint.mdc`](ai/rules/markdownlint.mdc) | All `.md`/`.mdc` files | Run `npx markdownlint-cli2 --fix <file>` after every Markdown create/edit |
| [`documentation.mdc`](ai/rules/documentation.mdc) | All code changes | Keep `docs/` in sync; update config reference, API docs, and feature docs |
| [`java-testing.mdc`](ai/rules/java-testing.mdc) | `**/*Test*.java` | AssertJ, Awaitility, `@ParameterizedTest`, `@Nested`, UAA-specific patterns |
| [`shellcheck.mdc`](ai/rules/shellcheck.mdc) | `**/*.sh` | Run `shellcheck <file>` after every shell script create/edit |
| [`ai-instructions.mdc`](ai/rules/ai-instructions.mdc) | Changing `ai/rules/` | Keep `AGENTS.md`, `CLAUDE.md`, and `copilot-instructions.md` in sync |

See [`ai/README.md`](ai/README.md) for full documentation on the AI setup.

## First-time setup (Cursor)

Run once after cloning to wire Cursor to `ai/rules/` and `ai/skills/`:

```bash
./scripts/setup_cursor.sh
```
