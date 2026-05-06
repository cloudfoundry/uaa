# GitHub Copilot Instructions

This repository uses a single source of truth for AI agent rules and skills located in
`ai/rules/` and `ai/skills/`. Read all `.mdc` files in `ai/rules/` before making changes.

## Rules

- **`ai/rules/markdownlint.mdc`** — After creating or editing any `.md` or `.mdc` file run
  `npx markdownlint-cli2 --fix <file>`.
- **`ai/rules/documentation.mdc`** — Keep `docs/` in sync with all code changes:
  configuration changes update `docs/UAA-Configuration-Reference.md`; API changes update
  `*Docs.java` files and require `./gradlew generateDocs`.
- **`ai/rules/java-testing.mdc`** — Use AssertJ for assertions, Awaitility for async
  waits, `@ParameterizedTest` instead of loops, `@Nested` for grouped tests, and
  `@DefaultTestContext` for UAA integration tests. (PRs, issues, workflows).
- **`ai/rules/shellcheck.mdc`** — Run `shellcheck <file>` after every shell script
  create/edit.
- **`ai/rules/ai-instructions.mdc`** — When changing `ai/rules/`, update the summary
  in `AGENTS.md`, `CLAUDE.md`, and this file.

## Working plans

Write ephemeral working plans to `ai/plans/` (gitignored). Do not commit plan files.

See `ai/README.md` for full documentation on the AI setup.
