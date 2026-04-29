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

## Codebase quick reference

UAA is a multi-module Gradle project. `server/` holds virtually all business logic;
`uaa/` is the thin Spring Boot entry point. See `AGENTS.md` for the full architecture
overview, build commands, database migration conventions, and testing patterns.

Key points:

- Every request runs in an **IdentityZone** context — always use
  `identityZoneManager.getCurrentIdentityZoneId()`, never hardcode the `uaa` zone.
- DB migrations (Flyway) must be added to all three directories:
  `hsqldb/`, `mysql/`, `postgresql/`.
- Dependencies are declared centrally in `dependencies.gradle` as named aliases; use
  those aliases in `build.gradle` files.
- Use **AssertJ** for assertions, **JUnit 5** only (no JUnit 4 vintage engine).
