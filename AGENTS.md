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

---

## Codebase Overview

### Architecture

The CloudFoundry UAA is a multi-tenant OAuth2/OIDC identity server built on Spring Boot.
It is a multi-module Gradle project:

| Directory | Artifact | Role |
| --- | --- | --- |
| `model/` | `cloudfoundry-identity-model` | Shared domain objects |
| `server/` | `cloudfoundry-identity-server` | Core REST API, SCIM, security, DB, LDAP |
| `uaa/` | `cloudfoundry-identity-uaa` | Spring Boot executable WAR; wires everything via `UaaBootConfiguration` |
| `statsd-lib/` + `statsd/` | `cloudfoundry-identity-statsd[-lib]` | Metrics publishing via StatsD |
| `metrics-data/` | `cloudfoundry-identity-metrics-data` | Metric definitions |

`server/` contains virtually all business logic. `uaa/` is the thin Spring Boot entry
point; `uaa/src/main/resources/uaa.yml` is the primary configuration file (overridden at
runtime by `$CLOUDFOUNDRY_CONFIG_PATH/uaa.yml` or `$UAA_CONFIG_PATH/uaa.yml`).

### Multi-tenancy (Identity Zones)

Every request runs in the context of an `IdentityZone` stored in `ThreadLocal` via
`IdentityZoneHolder` (deprecated — prefer injecting `IdentityZoneManager`). The `uaa`
zone is the system/default zone. Zone switching at the HTTP boundary is handled by
`IdentityZoneSwitchingFilter` (reads `X-Identity-Zone-Id` / `X-Identity-Zone-Subdomain`
headers; callers need `zones.<zone-id>.admin` scope).

**When adding any zone-aware feature**, always query/write using the current zone ID
(`identityZoneManager.getCurrentIdentityZoneId()`), never assume the `uaa` zone.

### Database and migrations

- Three supported databases: **HSQLDB** (default/in-memory), **PostgreSQL**, **MySQL**.
- Schema migrations use **Flyway**; SQL scripts live in
  `server/src/main/resources/org/cloudfoundry/identity/uaa/db/{hsqldb,mysql,postgresql}/`.
- New migration files must be added to **all three** database directories.
- Migration version format: `V<major>_<minor>__Description.sql`
  (e.g. `V4_113__Add_group_membership_idz_origin_idx.sql`).
- Non-FIPS BouncyCastle variants are globally excluded; use only the FIPS variants
  (`bc-fips`, `bctls-fips`, `bcpkix-fips`).

### Build and run

```bash
# Run the server (kills any existing UAA first)
./gradlew run

# Run with a real database
./gradlew -Dspring.profiles.active=mysql run
./gradlew -Dspring.profiles.active=postgresql run

# Debug (attach on port 5005; -Pdebugs suspends until debugger connects)
./gradlew run -Pdebug
./gradlew run -Pdebugs -PdebugPort=5006

# Build the executable WAR
./gradlew :clean :assemble

# Generate API docs (requires Ruby 3.3.8 + bundler)
./gradlew generateDocs
```

Server starts at `http://localhost:8080/uaa`. Config for local runs lives in
`scripts/boot/`.

### Testing

**Test types:**

- Unit tests: `./gradlew test` (HSQLDB by default)
- Integration tests (MockMvc / full Spring context): `./gradlew integrationTest`
- Docker-wrapped suites: `./run-unit-tests.sh <dbtype>` /
  `./run-integration-tests.sh <dbtype>`

**Key annotations:**

| Annotation | Use |
| --- | --- |
| `@DefaultTestContext` | Full Spring Boot context + MockMvc for `cloudfoundry-identity-uaa` tests |
| `@WithDatabaseContext` | Lightweight DB-only context for `cloudfoundry-identity-server` tests |
| `@EnabledIfProfile({"mysql","postgresql"})` | Run test only on specified DB profiles |
| `@DisabledIfProfile({"mysql"})` | Skip test on specified DB profiles |

Always run with `--no-daemon` when using real databases to avoid exhausting the 24
pre-created test databases (`uaa_1`…`uaa_24`):

```bash
./gradlew test --no-daemon
./gradlew '-Dspring.profiles.active=postgresql' test --no-daemon
```

Start real DB infrastructure first:

```bash
docker compose --file scripts/docker-compose.yml up [postgresql|mysql]
```

Run a single test class:

```bash
./gradlew :cloudfoundry-identity-server:test \
  --tests "org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManagerTests"
```

### Key conventions

- **Lombok** everywhere for boilerplate (`@Getter`, `@Builder`, etc.); configured in
  `lombok.config`.
- **AssertJ** for assertions. Legacy `hamcrest-all/core/library` artifacts are globally
  excluded.
- **JUnit 5** with `useJUnitPlatform()`. No JUnit 4 vintage engine.
- All dependencies declared centrally in `dependencies.gradle` as named aliases
  (e.g. `libraries.springBeans`, `libraries.nimbusJwt`); use these in `build.gradle`
  files, not inline coordinates.
- Spring profiles (`hsqldb`, `mysql`, `postgresql`, `ldap`, `saml`) gate both runtime
  behaviour and test infrastructure.

### Integration points

- **LDAP**: `spring_profiles: ldap` in `uaa.yml`; local dev setup in `scripts/ldap/`.
- **SAML**: `spring_profiles: saml`; test certificates in `scripts/saml/`.
- **SMTP**: Configurable via `smtp.host` / `smtp.port` (default `localhost:2525`); used
  for invite/reset flows.
- **StatsD metrics**: Enabled via `-Dstatsd.enabled=true`; implementation in
  `statsd-lib/`.
- **API docs**: Generated by `spring-restdocs` from tests in `uaa/src/test/java`,
  rendered via Slate (Ruby) into `uaa/build/docs/`.
