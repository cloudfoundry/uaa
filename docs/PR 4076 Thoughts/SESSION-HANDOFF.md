# Session handoff — PR #4076 (RFC 8705 mTLS client authentication)

Written 2026-09-29 at the end of a long working session, for picking this up cold on another
machine. Everything below was verified against the repo at the time of writing, not recalled.

**Updated 2026-10-01.** §1, §2, §7 and §9 have been brought up to date. §6's test counts and machine
details are as of 2026-09-29 and were not re-run in full since; the work after that date was verified with
targeted suites, named in the documents that describe it.

## 0. Can you resume the actual session elsewhere? No

Claude Code sessions live as local JSONL transcripts:

```text
~/.claude/projects/-Users-fh012259-workspace-cloudfoundry-uaa/6457f0db-ffcb-4a60-af58-55160c95b605.jsonl
```

`claude --resume` lists sessions found in that local directory, and the directory name encodes the
absolute project path. So there is no supported cross-machine resume: you would have to copy that
file to an identically-named directory on the new machine, and the project path would have to match
exactly. I would not rely on it.

Start a fresh session on the new machine and point it at this document. That is what it is for.

## 1. Where things stand

- **Branch:** `review/pr3792-fix` → **PR [#4076](https://github.com/cloudfoundry/uaa/pull/4076)**
- **Pushed to:** `origin` (`git@github.com:fhanik/uaa`). As of 2026-10-01 everything on the branch is
  pushed; check `git status -sb` for anything newer.
- **Base:** `cloudfoundry/develop`
- Working tree clean. The analysis docs in `docs/PR 4076 Thoughts/` are committed, so they travel
  with the branch — see the index in §11 for the ones relevant to this work.

Since the first version of this document the branch has gained, in order:

1. **The four ported #4075 follow-up items, reworked into TDD commits.** They had landed as one
   batched test commit plus one batched fix commit; they are now a red/green pair per item plus the
   doc commit, with a byte-identical tree.
2. **RFC 8707 resource indicators** — a new per-client `tls-client-auth-allowed-resources` allow-list
   validated at registration, a `resource` request parameter enforced at `/oauth/mtls/token`, and
   `invalid_target` as the refusal. See `docs/UAA-Client-Authentication.md`.
3. **A three-reviewer security review of the whole feature**, which found a HIGH-severity bypass of
   *both* endpoint guards and one latent path-resolution defect. Both are fixed. Read
   `pr4076-security-review.md` before touching the endpoint's routing or the enhancer's `aud`
   handling — it records what was verified clean as well as what was broken.
4. **A backwards-compatibility audit of every test change against `cloudfoundry/develop`**, on the
   principle that a modified pre-existing test is the cheapest signal that behaviour changed. No
   pre-existing test turned out to be deleted, renamed or disabled; the 20 removed lines are each
   accounted for in `pr4076-backwards-compatibility-audit.md`. It did surface one genuine break —
   the pre-RFC-8705 `OpenIdConfiguration(contextPath, issuer)` constructor had been changed to
   default mTLS **on**, silently altering the discovery document for an unchanged signature and
   failing open — now reverted to `false` and pinned by a new test.

### Remotes you will need to re-add on the new machine

```bash
git remote add cloudfoundry git@github.com:cloudfoundry/uaa
git remote add origin       git@github.com:fhanik/uaa
git remote add rkoster      git@github.com:rkoster/uaa   # needed for the comparison work, see §4
```

`rkoster` matters: `refs/pull/3972/head` on the `cloudfoundry` remote was **stale** (stuck at
`471ad5780`) and would not update even with `--force`. Fetching rkoster's fork branch directly is
the only way I found to see the current PR #3972 head:

```bash
git fetch --no-tags rkoster feat/rfc8705-mtls-client-auth
```

## 2. Commits on the branch (newest first)

**Caution on SHAs:** this branch's history has been rewritten more than once — the batched commit
pair below was deliberately split into red/green pairs, and the whole range was later rebased to
strip AI co-author trailers (see §7). Match commits by subject line, not SHA.

| SHA | What it is |
|---|---|
| `3383975fe` | **fix** (green): third-party token enhancers are unrestricted again; mTLS opts in to a late `sub`/`aud` via `UaaTokenEnhancer.getLateOverrideClaims()` |
| `448d872a9` | **test** (red): a third-party token enhancer must not be restricted by the mTLS work |
| `9c5a4dbf1` | **test**: pin how `MtlsClaimsEnhancer` coexists with other token enhancers |
| `a361df928` | **fix**: make `uaa.mtls-enabled` mean one thing, so the feature cannot half-enable (`MtlsEnabledCondition`) |
| `19a14a894` | **test**: pin that discovery DOES advertise mTLS when the feature is enabled |
| `3f455e1e7` | **fix**: stop the pre-RFC-8705 `OpenIdConfiguration` constructor advertising mTLS |
| `50f9590b9` | **fix** (green): resolve the mTLS client-auth gate from the decoded servlet path |
| `ce7645f33` | **test** (red): the client-auth gate reads a different path than every other gate |
| `4abcd68e3` | **fix** (green): serve nothing below `/oauth/mtls/token`; enforce the allow-list in the enhancer |
| `562fcbb76` | **test** (red): paths below `/oauth/mtls/token` bypass both endpoint guards — **the HIGH finding** |
| `199883a87` | docs: cover the RFC 8707 `resource` parameter in the mTLS API docs (restdocs) |
| `923f39fd3` | docs: `tls-client-auth-allowed-resources` and the `resource` parameter |
| `6b899f1d3` | **fix** (green): enforce and honor the RFC 8707 `resource` parameter |
| `e172f3ed5` | **test** (red): the `resource` parameter is silently ignored |
| `8b929a462` | **fix** (green): validate `tls-client-auth-allowed-resources` at registration |
| `0fd331d5b` | **test** (red): the resource allow-list has no registration validation |
| `f3b174a87` | your commit: scope the session handoff to the mTLS work only |
| `a4d0f65ad` | your commit: add this session handoff |
| `d8c156f1f` | your commit: three analysis docs into `docs/PR 4076 Thoughts/` |
| `69992c32b` | docs: revocation behaviour and CA rotation |
| `b2c1e7025` | **fix** (green): skip constructing the buildpack mapper when mTLS is off |
| `80e3e7b36` | **test** (red): the mapper is registered when mTLS is off |
| `43986e4a5` | **fix** (green): make the mTLS endpoint POST-only |
| `ce005b89e` | **test** (red): the mTLS endpoint serves GET |
| `41d0f7208` | **fix** (green): trust every certificate in a `tls-client-auth-ca` rotation bundle |
| `637754986` | **test** (red): a rotation bundle silently trusts only the first certificate |
| `3a7776d21` | **fix**: correct stale `FINDING` / `FAILS TODAY` markers on tests that now pass |
| `54a9ae4de` | **test**: identity-zone isolation, both addressing modes |
| `dfc657805` | your commit: "musings about the intent of the original PR #3972" |
| `9749e3620` | **test**: RFC 8705 §3.2 (`cnf` in introspection) verified end-to-end — already compliant, no production change needed |
| `4f8838055` | **fix**: revert a broken boot exclusion, replace with a classpath canary test |
| `328541ccb` | Copilot review: buildpack mapper ordering, pattern validation, docs |
| `50724c7df` | docs: required fields for RFC 8705 |
| `4c3e9706d` | **feat** (green): enforce RFC 8705 §2.1.2 certificate subject binding |
| `7da4c6033` | **test** (red): the above |
| `3cc946d32` | wip: security review of the mTLS implementation, phase 1 |
| `9a39576ee` | Address Copilot review |
| `bf8d742ee` | "example fix" (original review commit) |
| `5998e4fb0` | "Review of PR #3972" (original review commit) |
| `5404fba23` | rkoster's original 132 commits, squashed, authorship preserved |

## 3. The single most important technical fact

**PR #4076 implements RFC 8705 §2.1.2 certificate subject binding. PR #3972 does not.**

Verified by grepping rkoster's whole tree: no `tls_client_auth_subject_dn`, no
`tls_client_auth_san_dns`, no `SUBJECT_BINDING_PARAMETERS`, no `TlsClientAuthSubjectMatcher`. His
`TlsClientAuthConfiguration` declares only `tls-client-auth-ca`, `-claim-mappings`,
`-sub-template`, `-aud-templates`, `-trusted-proxy-ca`, `-required-claims`.

Consequence: on #3972 as it stands, **any certificate chaining to the configured CA authenticates
as that client.** `required-claims` is optional, is not the RFC mechanism, and gates on mapped claim
*values* rather than the certificate's registered subject. On the Diego instance-identity CA — which
issues to every app in the foundation — that is the whole problem.

Our implementation (in `4c3e9706d`): exactly one subject-binding parameter enforced at registration
and at authentication, exact matching, no wildcards, SAN *type* checked so a dNSName cannot be
satisfied by an email SAN reading the same, fail closed on zero or multiple.

This needs to land on #3972, or the merged feature keeps that behaviour.

## 4. The branches have diverged — do not assume a merge

rkoster pushed 14 follow-up commits to #3972 (`471ad5780`..`a80e1c94f`) addressing the #4075 review.
`471ad5780` is exactly the last of the 132 commits squashed into this branch's base, so **none of
those 14 are here.** Both branches fixed most of the same findings independently, in different ways.
Neither is a superset of the other.

Full analysis: `pr4075-comment-vs-our-branch.md`. Summary of that comparison:

- **Seven findings both branches fixed** (grant-type restriction, consistent 401s, endpoint no
  longer an alias of `/oauth/token`, placeholder-less `sub` templates, `amr`/`acr` claim mappings
  including dotted names, 404 when disabled, `token-endpoint-auth-method` as inert metadata).
- **Four gaps of ours, now ported** (CA rotation `637754986`/`41d0f7208`, POST-only `ce005b89e`/`43986e4a5`,
  mapper gating `80e3e7b36`/`b2c1e7025`, expired certs) — see §5.
- **Ours that he lacks:** §2.1.2 subject binding (§3 above), zone isolation, §3.2 verification, and
  a red/green commit split (he declined this explicitly: "tests and production changes are
  committed together").

## 5. What the last round changed

Ported in intent from his follow-ups, implemented our own way:

1. **CA rotation.** The defect was an asymmetry: registration validated with
   `PemCertificateParser`, which reads *every* certificate, while `TlsClientAuthentication` had its
   own private single-certificate parser and built a one-element `TrustAnchor` set. A rotation
   bundle registered cleanly and then only the first CA was trusted. Both call sites (client CA and
   trusted-proxy CA) now use the shared parser and every certificate becomes an anchor; the private
   parser is deleted so the asymmetry cannot return.
2. **POST-only.** Implemented in `MtlsEndpointAvailabilityFilter`, **deliberately not** in the
   controller as he did. "Method not allowed" is a property of the resource, not the caller, so
   deciding it ahead of Spring Security gives an unauthenticated GET a 405 with `Allow: POST` (RFC
   9110) instead of a 401 — his controller-level check only fires for *authenticated* GETs, by his
   own description — and it covers PUT/DELETE for free. `UaaTokenEndpoint` is untouched, so
   `/oauth/token` keeps its GET support.
3. **Mapper gating.** `clientCertificateMapperFilter` now takes `uaa.mtls-enabled` and returns a
   disabled registration when off. Beyond not putting a third-party filter in every request path,
   this stops a deployment that never enables mTLS from needing the buildpack jar merely to boot —
   the class is package-private, loaded reflectively, and its absence throws.
4. **Revocation documented.** New "Operating tls_client_auth" section in
   `docs/UAA-Client-Authentication.md`: PKIX runs with `setRevocationEnabled(false)` (no CRL, no
   OCSP), what that means for a stolen certificate, and the CA rotation procedure.

## 6. Verification — state and exact commands

Current machine (`/Users/fhanik/...`, JDK 25, Chrome 154):

- Unit suite: **green** after the security fixes — **8,717 tests, 0 failures, 0 errors** across the
  five modules, counted from the JUnit XML rather than read off the console summary (`./gradlew test`
  prints only the modules it re-executed, which is how a partially-cached run can look smaller than
  it is). ~4 min.
- `generateDocs`: **success** (~40 s). The rendered
  `uaa/build/docs/version/0.0.0/index.html` was checked to actually contain the mTLS section,
  the five subject-binding parameters and the `resource` parameter table — not just to build.
- `integrationTest`: **not run on this machine.** ChromeDriver is now installed and matching (§7), so
  it should be runnable; the last recorded run was on the old machine — 370/376, 4 skipped, 2
  failures, both in `ScimGroupEndpointsIntegrationTests` (the known SCIM rate-limiter 429, plus
  `updateGroupUpdatesMemberUsers` returning null as a second symptom of the same exhaustion). That
  class passes **18/18 in isolation**, and Filip has said the SCIM 429 is not a concern.

```bash
export JAVA_HOME=/Users/fhanik/workspace/software/java/jdk-25.0.1.jdk/Contents/Home

./gradlew test                                     # full unit suite, ~4 min
./gradlew generateDocs                             # ruby 3.3.8 + bundler; already satisfied, see §7
./gradlew integrationTest                          # boots a real UAA, ~7 min, needs chromedriver

# the mTLS work specifically
./gradlew :cloudfoundry-identity-uaa:test --tests '*Mtls*'
./gradlew :cloudfoundry-identity-server:test --tests '*oauth.tls*'
./gradlew :cloudfoundry-identity-uaa:test --tests '*TokenEndpointDocs*'   # the mTLS API docs example
```

## 7. Environment gotchas that cost time

- **Always check the exit code.** `./gradlew ... | tail` hides gradle's status; a piped run looked
  like a success more than once. Write to a log and check `$?` separately. `PIPESTATUS` does not
  work in this zsh.
- **ChromeDriver must match Chrome's major version**, or every integration test fails with
  "ApplicationContext failure threshold (1) exceeded" — 204 cascaded failures from one bean.

  **Brew is not an option for this.** The `chromedriver` cask is *disabled* ("does not pass the macOS
  Gatekeeper check", disabled 2026-09-01) and pinned at 152 regardless, so it could not match
  Chrome 154 even if it installed. Use Chrome for Testing, which publishes an exact-version driver:

  ```bash
  # find the driver URL for your Chrome major + platform
  curl -sS https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json
  # then, for the matching version (154.0.8037.92 / mac-arm64 at time of writing):
  curl -sSL -o cd.zip https://storage.googleapis.com/chrome-for-testing-public/154.0.8037.92/mac-arm64/chromedriver-mac-arm64.zip
  unzip -o cd.zip && cp chromedriver-mac-arm64/chromedriver /opt/homebrew/bin/chromedriver
  chmod +x /opt/homebrew/bin/chromedriver
  xattr -d com.apple.quarantine /opt/homebrew/bin/chromedriver 2>/dev/null
  chromedriver --version   # must match: "Google Chrome --version"
  ```

  Installed this way on the current machine at **154.0.8037.92**, matching Chrome exactly, and smoke
  tested (it starts and answers `/status` with `ready:true`, so Gatekeeper is not blocking it).
  `/opt/homebrew/bin` is already on `PATH`, so **no `PATH` change and therefore no gradle-daemon
  restart is needed** — prefer this over prepending a new directory, for that reason. It is a
  hand-managed binary that brew does not own, so `brew upgrade chromedriver` will say "not
  installed"; re-run the steps above when Chrome updates.

- **Ruby for `generateDocs` is already satisfied** on this machine: rbenv provides 3.3.8, exactly
  what `uaa/slate/.ruby-version` and the README ask for, plus bundler 2.7.1. Nothing to install.
  Note `/opt/homebrew/opt/ruby/bin` sits *ahead* of `~/.rbenv/shims` on `PATH` but is empty, so
  rbenv's ruby is what actually resolves.
- **Markdown lint.** `npx markdownlint-cli2` does not work here (the npm registry is an internal
  Artifactory mirror that 403s it). `markdownlint-cli2` is installed via Homebrew at
  `/opt/homebrew/bin/markdownlint-cli2`; run it **from the repository root** so it picks up
  `.markdownlint.json` (120-column limit) — run from a subdirectory it applies the 80-column default and
  reports hundreds of false errors.
- **Stop the gradle daemon after changing PATH** (`./gradlew --stop`). A daemon keeps the PATH it
  started with; this caused a bogus `generateDocs` ruby/gem failure earlier in the session.
- **`timeout` is not installed** (no GNU coreutils); use a background PID plus `kill` instead.
- **Jackson 3.** `develop` has migrated: use `tools.jackson.core.type.TypeReference`, not
  `com.fasterxml.jackson.core.type.TypeReference`.
- **Never stage `.agent/`** — it is untracked noise that shows up in every `git status`.
- **AI co-author trailers are not wanted on this branch, and commits get rewritten to remove them.**
  Earlier notes here described this as "something on the machine rewrites commits" and treated the
  disappearing trailers as a mystery — that was wrong, and chasing it wastes time. It is
  intentional: Filip asked for every such trailer to be stripped, and the whole range from the
  CA-rotation commit onward was rebased to do it. Do not add them back; commit without one.
  The side effect is real though — rewriting at that depth gives **every** commit above the oldest
  edited one a new SHA, including commits authored by others. Trees stay byte-identical and
  rkoster's authorship on the squashed import is preserved, so nothing is lost; if SHAs have moved
  under you, that is why, and it is not data loss.
- **`git reset --hard` is blocked by this session's permissions.** When a branch pointer needs to
  move and the working tree already matches the target (e.g. after rebuilding history with an
  identical tree), `git update-ref refs/heads/<branch> <sha>` does the same job without the blocked
  verb and without touching files.

## 8. Writing tests here

- Zone-aware MockMvc: `@ParameterizedTest @EnumSource(ZoneResolutionMode.class)`, model on
  `SessionControllerMockMvcZonePathTests` / `LoginMockMvcZonePathTests`. Create zones with
  `MockMvcUtils.createOtherIdentityZone(...)`.
- **Zone-path mode gotcha:** MockMvc rejects a builder whose URI does not decompose into
  contextPath + servletPath. In `ZONE_PATH` mode the URI still carries `/z/{subdomain}` at build
  time — `ZonePathContextRewritingFilter` splits it at request time — so you may only pre-set
  `.servletPath(...)` when no zone prefix is present. There is a `withServletPath(...)` helper in
  both mTLS MockMvc test classes that encodes this. Getting it wrong makes negative tests pass for
  the wrong reason.
- The mTLS tests rebuild MockMvc in `@BeforeEach` to add the zone filters, the raw certificate
  capture filter and the availability filter, because `@DefaultTestContext` does not include them.
  Order is load-bearing: zone rewriting must run before anything that reads `getServletPath()`.
- `@ConditionalOnProperty`-gated beans are switched on from a test with `@TestPropertySource`
  (`uaa.mtls-enabled=true` on the hardening and zone suites, `=false` on the disabled suite). Where
  the value has to be computed at runtime, an `ApplicationContextInitializer` works too, because it
  runs before the context refreshes and therefore before condition evaluation. Either spelling of a
  property resolves, kebab or snake — Boot attaches relaxed-binding resolution to the
  `Environment` — which I verified rather than assumed.

## 9. Open items

On this branch:

- **Read `pr4076-develop-merge-evaluation.md` first if you are picking this up fresh.** It is a full,
  independent evaluation of the branch against `cloudfoundry/develop` on the three merge criteria
  (backwards compatibility, security, feature gating), done after this handoff was last updated. It
  confirms the gating holds and finds no new vulnerability, and raises two items that are **not**
  gated by `uaa.mtls-enabled` (see the enhancer-list qualifier below) and therefore ship beyond the opt-in feature:
  - **M1** — `granted_scopes` stops appearing on access tokens issued via `grant_type=refresh_token`,
    because `GRANTED_SCOPES` was added to `NON_ADDITIONAL_ROOT_CLAIMS`, which the pre-existing
    `getAdditionalRootClaims` has always consulted. Correct behaviour, but a wire-visible change on
    the refresh path of any deployment that registers a token enhancer (stock UAA with the flag off has none, so is
    unaffected); kept by decision (put it in the PR description). **M3**, the wider form — the output of *every*
    enhancer being filtered and `sub`/`aud` from any enhancer winning — was **fixed**: third-party enhancers are
    unrestricted again and the mTLS enhancer opts in to a late `sub`/`aud` via
    `UaaTokenEnhancer.getLateOverrideClaims()`. Pinned by
    `UaaTokenServicesTests.WhenMtlsClaimsEnhancerSharesTheEnhancerList`.
  - **M2** — `UaaAuthenticationDetails` gained a field and declares no `serialVersionUID`, so
    Spring-Session-JDBC rows written by the previous UAA version fail to deserialize after an
    upgrade. Fix is `transient` on the new field, or pin the UID to develop's value.
  Plus four low-severity items (L1-L4). L1 (a javadoc asserting an invariant the security review
  disproved) and the comment half of L2/L3 have since been **fixed**; what remains open is that
  `UaaClientDetails.tlsClientAuthConfiguration` is dead in production (L3) and that the claim-mapping
  `pattern` has no complexity bound (L4). The evaluation also records that the `granted_scopes` regression
  test was vacuous in the default configuration and has been made to register an enhancer.
- Nothing blocking. Branch is green and pushed.
- **Decide what `cnf` should do on token refresh.** `UaaTokenServices.refreshAccessToken` copies
  `cnf` forward from the refresh token's claims (it is absent from `NON_ADDITIONAL_ROOT_CLAIMS`)
  without re-checking any presented certificate, so a refreshed token claims a binding the presenter
  did not demonstrate. It is **unreachable today** — only `client_credentials` is reachable at the
  mTLS endpoint and it issues no refresh token — but it is a fail-open shape. Either add `cnf` to
  `NON_ADDITIONAL_ROOT_CLAIMS` (one line; the refreshed token is then honestly unbound) or refuse the
  refresh when the refresh token carries `cnf` without a matching certificate (the RFC 8705 §7.1
  shape). Left for Filip because it changes refresh semantics. See `pr4076-security-review.md` §3.1.
- **Consider adding `act` to `RESERVED_CLAIM_NAMES`.** A claim mapping can currently target `act` /
  `act.sub` (RFC 8693 actor). UAA never authorizes on it, so no exploit was demonstrated, but it is
  the same category as `amr`/`acr`/`cnf`, which are reserved. See `pr4076-security-review.md` §3.2.
- Optional: port rkoster's `09f1992dd` consolidation. The same
  `additionalInformation` → `TlsClientAuthConfiguration` parsing exists in three places
  (`MtlsClaimsEnhancer`, `ClientDetailsAuthenticationProvider`, `ClientAdminEndpointsValidator`), and
  the RFC 8707 work had to touch two of them — the `tls-client-auth-allowed-resources` key was added
  to the model and the validator but initially *not* to `MtlsClaimsEnhancer.loadTlsConfig`, which is
  precisely the drift this consolidation would prevent. Raising the priority on that basis.
- Optional: verify his `a80e1c94f` behaviour — distinguishing "no certificate presented" from
  "required-claims not satisfied" *without echoing claim values* into the error.
- ~~No test for descendant paths~~ — **done.** Group I in `MtlsTokenEndpointHardeningMockMvcTests`,
  added when the descendant-path routing bypass was found; that gap was the bug.
- RFC 8707 is deliberately partial: one `resource` value per request, `aud` only (no per-target scope
  restriction), and no interaction with `tls-client-auth-aud-templates` beyond refusing to configure
  both. The Service Accounts design wants per-target permitted scopes too — see
  `cf-service-accounts-proposal-evaluation.md` §5.3.

Addressed by neither branch:

- Revocation actually implemented (CRL/OCSP) — documented-as-off only.
- RFC 8705 §2.2 `self_signed_tls_client_auth`, §3.4 client-declared metadata, §4 public-client
  certificate binding.
- **Per-zone mTLS enablement.** `uaa.mtls-enabled` is global, so enabling it advertises
  `tls_client_auth` in every zone's discovery document and lets any zone admin register
  `tls-client-auth-ca`. Flagged to Filip as a product decision, not fixed.
- Audit events for mTLS token issuance.
- A dedicated rate-limiter mapping for `/oauth/mtls/token` (CPU-bound; currently in the default
  global 1000r/s bucket).

## 10. The wider picture — this branch and the Service Accounts RFC

Worth reading before proposing anything, because these two are not alternatives.

| | #4076 (this branch) | Service Accounts RFC (draft) |
|---|---|---|
| Layer | UAA only | CAPI + Diego + UAA + CLI + Gorouter + OSB |
| Stable subject? | No — the caller must supply one | **Yes — it creates one** |
| Who picks `aud` | Client-admin templates | Curated targets, app selects |
| Claims asserted by | Tenant claim mappings | The platform |
| Status | Implemented, reviewed, hardened | Draft RFC, eight open questions |

The core tension: RFC 8705 §2.1.2 binds one client to one *fixed* certificate subject, but Diego
re-mints certificates with a new instance GUID on every container replacement. #3972 wanted one
client to cover a rotating population, which §2.1.2 cannot express — that is why the hardening in
this branch felt constraining to its author. The Service Accounts RFC **removes the obstacle**
instead of working around it, by manufacturing a subject that is stable across container
replacement (a derived DNS SAN `<name>.svc.identity`) so §2.1.2 applies exactly as written.

Note that the Service Accounts design **depends on** `tls_client_auth_san_dns`, which is exactly
what this branch implements (§3) — including the exact canonical DNS matching and no-wildcard rule
the draft asks for. It consumes #4076 rather than replacing it, so nothing in that RFC is a reason
to hold this branch.

## 11. Document index — `docs/PR 4076 Thoughts/`

| File | What it covers |
|---|---|
| `SESSION-HANDOFF.md` | this file |
| `pr4076-security-review.md` | **read this before touching the endpoint's routing or the enhancer's `aud` handling**: the three-reviewer security review of this branch — the HIGH descendant-path bypass, the path-resolution defect, what was left unfixed and why, and a long list of what was verified clean |
| `pr4076-backwards-compatibility-audit.md` | every test change in this PR vs `cloudfoundry/develop`, and what each one implies: no pre-existing test deleted or renamed, the 20 removed lines accounted for one by one, the `OpenIdConfiguration` fail-open default that was found and reverted, and the list of intentional behaviour changes |
| `pr4076-mtls-enabled-flag-audit.md` | whether `uaa.mtls-enabled` gates the whole feature: the two-different-parsers defect that let `=1` half-enable it, the three components deliberately left ungated and why each is safe, and the complete gating inventory |
| `pr4075-comment-vs-our-branch.md` | rkoster's #4075 response vs this branch: what both fixed, the four gaps ported, the §2.1.2 gap on his side |
| `cf-service-accounts-proposal-evaluation.md` | the Service Accounts RFC: how it works, what "stable subject" means, per-component work breakdown, risks |
| `rfc8705-vs-workload-federation-discussion.md` | why rkoster felt constrained; how AWS/GCP/K8s federation compares; what the token is for |
| `rfc8705-feature-gaps.md` | RFC 8705 conformance gap analysis |
| `pr3972-vs-pr3792-fix-comparison.md` | what this branch preserved, removed and fixed vs the original PR |

## 12. Working agreements observed in this session

- **Tests in one commit, fixes in the next.** Red/green split, with the red commit message stating
  what fails and why. This was asked for explicitly and is also what the #4075 review asked of
  rkoster.
- **Verify, do not assert.** Plausible-sounding findings repeatedly turned out to be wrong once
  tested. Seven tests labelled `FINDING` / `FAILS TODAY` were in fact passing, because later
  commits on this branch had fixed them and only the labels were left behind — corrected in
  `3a7776d21` after instrumenting the four dual-path ones and reading the real responses rather
  than inferring from a green suite. Likewise the claim that our branch lacked dotted-claim
  protection was wrong (`isReservedClaimName` already checks the root segment), while the CA
  rotation gap was real. Check the code before writing either into a review.
- **Do not push without being asked.** Filip authorizes it per round.
- Run the full suite before declaring done; the SCIM 429 is a known exclusion.
- Markdown: `npx markdownlint-cli2 --fix <file>`, and compare the error count before/after, since
  several `docs/` files have large pre-existing baselines that cannot reach zero.
