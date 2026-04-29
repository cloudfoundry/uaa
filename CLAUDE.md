# Claude Code Guidelines

This repository uses a single source of truth for AI agent rules and skills:

- **Rules:** [`ai/rules/`](ai/rules/) — read all `.mdc` files here before starting any task.
- **Skills:** [`ai/skills/`](ai/skills/) — reusable task patterns (added here as they are identified).
- **Plans:** `ai/plans/` — write working plans here; this directory is gitignored.

## Rules summary

| File | Applies to | Summary |
| --- | --- | --- |
| [`markdownlint.mdc`](ai/rules/markdownlint.mdc) | All `.md`/`.mdc` files | Run `npx markdownlint-cli2 --fix <file>` after every Markdown create/edit |
| [`documentation.mdc`](ai/rules/documentation.mdc) | All code changes | Keep `docs/` in sync; update config reference, API docs, and feature docs |
| [`java-testing.mdc`](ai/rules/java-testing.mdc) | `**/*Test*.java` | AssertJ, Awaitility, `@ParameterizedTest`, `@Nested`, UAA-specific patterns |
| [`shellcheck.mdc`](ai/rules/shellcheck.mdc) | `**/*.sh` | Run `shellcheck <file>` after every shell script create/edit |
| [`ai-instructions.mdc`](ai/rules/ai-instructions.mdc) | Changing `ai/rules/` | Keep `AGENTS.md`, `CLAUDE.md`, and `copilot-instructions.md` in sync |

See [`ai/README.md`](ai/README.md) for full documentation on the AI setup.

## Key documentation files

- **Configuration reference:** `docs/UAA-Configuration-Reference.md`
- **API test/doc sources:** `uaa/src/test/java/**/*Docs.java`
- **Feature docs:** `docs/*.md`
