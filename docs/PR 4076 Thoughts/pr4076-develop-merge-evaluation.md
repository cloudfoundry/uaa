# PR #4076 — merge evaluation against `cloudfoundry/develop`

An independent, full-branch evaluation of what merging this branch into `cloudfoundry/develop`
would do, against the three criteria that matter for the merge decision:

1. **backwards compatibility** — nothing an existing deployment relies on changes;
2. **security** — the feature, when enabled, is sound;
3. **gating** — nothing of the feature acts on a deployment that has not enabled it.

This is deliberately a *fresh* pass rather than a summary of the audits already on the branch
(`pr4076-backwards-compatibility-audit.md`, `pr4076-mtls-enabled-flag-audit.md`,
`pr4076-security-review.md`). Where it reaches the same conclusion as one of those, it says so in one
line and moves on; the body below is what those documents do **not** already record.

## 0. Method and scope

```bash
MB=$(git merge-base HEAD cloudfoundry/develop)   # 6cc0371111542e60ef64d9beb8bf42068b85bdb8
git diff --stat $MB..HEAD                        # 94 files, +13935 / -53, 40 commits
```

Every non-test, non-doc file in the diff was read in full (≈2,700 lines of production change across
38 files). Verified by running, not by reading alone:

| Suite | Result |
|---|---|
| `:cloudfoundry-identity-server:test` — `oauth.tls.*`, `web.tomcat.*`, `ClientAdminEndpointsValidatorTests`, `ClientDetailsAuthenticationProviderTests`, `ZoneEndpointsClientDetailsValidatorTests` | green |
| `:cloudfoundry-identity-model:test` (whole module) | green |
| `:cloudfoundry-identity-uaa:test` — `MtlsDisabledTokenEndpointMockMvcTests`, `MtlsFlagConsistencyMockMvcTests`, `UaaTokenServicesTests` | green |

## 1. Verdict

| Criterion | Verdict |
|---|---|
| Feature gating (`uaa.mtls-enabled`) | **Holds.** With the flag off, the endpoint 404s before any security chain, the Tomcat connector is untouched, the claims enhancer and the mTLS filter chain beans are absent, discovery advertises nothing, and all four client-registration paths refuse the config keys. Independently re-derived; matches the flag audit's inventory. |
| Security of the feature when on | **Sound, with the residual items already recorded** in `pr4076-security-review.md` §3 and `SESSION-HANDOFF.md` §9. No new vulnerability found in this pass. |
| Backwards compatibility | **One un-gated, wire-visible change is not recorded anywhere** — finding **M1** below, triggered by *any* token enhancer being registered rather than by the flag. (A second, **M3**, was found and has since been fixed.) One upgrade-time hazard not previously considered — **M2**. Everything else is additive or already documented. |

The merge-blocking question is therefore narrow: M1 and M2 are the only two items that affect a
deployment which never turns the feature on.

## 2. Findings

### M1 — `granted_scopes` disappears from refresh-issued access tokens, wherever a token enhancer is registered

**Not gated by `uaa.mtls-enabled` — gated by whether *any* `UaaTokenEnhancer` bean exists.
Severity: medium (compatibility), positive (security).**

> **Correction (2026-10-01).** An earlier version of this section said this affects every deployment. That is
> wrong for stock UAA. `getAdditionalRootClaims` only copies refresh-token claims inside
> `if (!uaaTokenEnhancers.isEmpty())`, and the only `UaaTokenEnhancer` in the main tree is
> `MtlsClaimsEnhancer` (flag-gated). So stock UAA with the flag off never copied `granted_scopes` and is
> unaffected. It **does** affect any deployment that registers its own enhancer — e.g. a distribution with
> additional closed-source enhancers — regardless of the flag. (The wider enhancer-output change found while
> following this through, **M3**, has been fixed; this one stays by decision.)

`UaaTokenServices.NON_ADDITIONAL_ROOT_CLAIMS` gains `GRANTED_SCOPES`
(`server/.../oauth/UaaTokenServices.java:143`). That set is consulted in two places, and only one of
them is new:

- the new enhancer-claims filter in `createJWTToken` (reached only when `uaaTokenEnhancers` is
  non-empty: the mTLS enhancer when the flag is on, **or any other enhancer the deployment registers**), and
- the **pre-existing** `getAdditionalRootClaims(refreshTokenClaims)`, which every
  `grant_type=refresh_token` call goes through but which only copies claims when `uaaTokenEnhancers` is
  non-empty — the same condition.

Before this branch, `granted_scopes` was copied out of the refresh token into
`additionalRootClaims` and then straight onto the new access token; the
`refreshTokenClaims.remove(GRANTED_SCOPES)` line below the copy loop operated on the source map
*after* the copy and therefore never had any effect. Adding the key to the filter set is what finally
enforces the intent that line was written for — so **refreshed access tokens stop carrying
`granted_scopes`** the moment this merges, for every deployment that has at least one token enhancer
(flag or no flag).

That is the right behaviour (a deliberately narrowed access token should not disclose the full
consented set, and the new test `UaaTokenServicesTests:500` pins it). The problem is that it is a
change to the content of a signed token on the refresh path of every enhancer-using deployment, shipped
by a PR whose stated scope is an opt-in feature. Any resource server reading `granted_scopes` off an
access token obtained via the refresh grant will stop finding it.

**Action:** add it to §3 of `pr4076-backwards-compatibility-audit.md` ("intentional behaviour
changes"), where it currently does not appear, and call it out in the PR description — it is the one
item in this PR that a UAA operator who will never enable mTLS but runs their own token enhancers still needs
to read. It is also a
candidate for splitting into its own PR, since it stands entirely on its own and would otherwise
land as a side effect of a feature merge.

### M2 — `UaaAuthenticationDetails` gained a field, which invalidates persisted sessions on upgrade

**Un-gated by `uaa.mtls-enabled`. Severity: medium (upgrade), needs one check before acting.**

`UaaAuthenticationDetails implements Serializable` and declares **no `serialVersionUID`**
(`server/.../authentication/UaaAuthenticationDetails.java:38`). This branch adds a
`private final String servletPath` field and a `public String getServletPath()` method to it
(commit `50f9590b9`). The JDK's default serialVersionUID is computed from the class's fields and
non-private method signatures, so **it necessarily changes**, and a stream written by the previous
version deserializes as `InvalidClassException: local class incompatible`.

Why that reaches a real deployment: the object is in the session graph — `UaaAuthentication`
(`implements Authentication, Serializable`) exposes it via `getUaaAuthenticationDetails()`, and the
security context is stored in the HTTP session, which UAA persists with Spring Session JDBC
(`server/build.gradle.kts` → `springSessionJdbc`; `UaaJdbcSessionConfig`). No custom
`springSessionConversionService` / serializer bean is defined anywhere in the tree, so
`JdbcIndexedSessionRepository` uses its default Java-serialization converters. Session rows outlive a
UAA restart by design, so the rows a pre-upgrade instance wrote are still there when the upgraded
instance reads them — during a rolling upgrade, concurrently.

Consequence: active browser sessions fail to deserialize after the upgrade. Best case users are
bounced to login; worse, the failure surfaces as an error on a request rather than a clean
"no session".

**Verify before acting** (one command, nothing here depends on the answer being yes):

```bash
# on cloudfoundry/develop, then on this branch:
serialver -classpath "$(…server runtime classpath…)" \
  org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails
```

**Two fixes, either sufficient:**

- mark `servletPath` `transient` — it is read only during the request that created it
  (`ClientDetailsAuthenticationProvider.isTlsClientAuthPath`), and a `null` after deserialization
  falls back to the `requestPath` reading, which is exactly the pre-branch behaviour; or
- pin `serialVersionUID` to the value `develop` computes, which freezes compatibility for this class
  going forward as well.

The second is the better long-term fix; the first is one keyword. Note this is a *latent repo
condition* this branch happens to trip, not something the branch invented — the class has never had
a `serialVersionUID` — which is an argument for fixing it properly here.

### M3 — every token enhancer's output was filtered, and `sub`/`aud` from any enhancer won — RESOLVED

**Status: fixed in `3383975fe` (red `448d872a9`).** Kept here because the original behaviour is what a reviewer of
the earlier commits will have seen, and because the contract it settles is worth stating.

**What it was.** The handling added to `createJWTAccessToken` for the mTLS enhancer's benefit was applied to the
merged output of **all** enhancers, because the enhancer list is one shared list. For a deployment with its own
enhancers — gated by that list being non-empty, not by `uaa.mtls-enabled` — it dropped UAA's protected claim names
from their output (`jti`, `user_name`, `email`, `auth_time`, `authorities`, … including ones UAA does not set for the
grant, which used to survive) and made their `sub`/`aud` win (which used to be overwritten and therefore ignored).

**The decision.** A third-party enhancer has to be free to do its own thing and is responsible for what it emits;
enabling mTLS must not change what it can do. So the mTLS work gets no say over other enhancers' output.

**What changed.**

- `createJWTAccessToken` is back to develop's handling for every enhancer: claims applied before UAA's defaults;
  UAA's defaults take precedence for the claims it sets itself.
- The one thing the mTLS enhancer needs — its certificate-identity `sub`/`aud` surviving those defaults — is an
  explicit **opt-in**: `UaaTokenEnhancer.getLateOverrideClaims()`, a `default` method returning an empty set, so
  existing implementations compile and behave unchanged. `MtlsClaimsEnhancer` returns `{sub, aud}`;
  `UaaTokenServices` applies, after its defaults, only the claims an enhancer both **named and returned**.
- The drop-list was redundant for mTLS to begin with: `MtlsClaimsEnhancer` already skips every reserved claim name
  itself and the registration validators reject them up front.

**Verified.** The flipped tests pass against develop's `UaaTokenServices` and failed on the branch before the fix;
1825 tests across the server and uaa `oauth` and mTLS MockMvc suites pass after it.

**Still true, and not a defect:** enhancers coexist in one list and each result is `putAll`-ed into a shared map,
so adding `MtlsClaimsEnhancer` loses none of the others; it returns an empty map unless the request authenticated
with `tls_client_auth`. On a collision on a custom claim name the later enhancer in the list wins, and
`MtlsClaimsEnhancer` has no `@Order`, so its position relative to other enhancers follows bean registration order
unless they declare one.

**Still deliberate (M1):** `GRANTED_SCOPES` remains in `NON_ADDITIONAL_ROOT_CLAIMS`. That filters what UAA copies
from a *refresh token*, not what an enhancer emits, and it fixes a real leak. It remains a visible change for any
deployment with enhancers, so it still needs to be in the PR description.

### L1 — `UaaTokenEndpoint.enforceResourceIndicator`'s javadoc asserts an invariant that was disproved

**Severity: low, but it is load-bearing documentation in security-critical code.**

The javadoc at `server/.../oauth/token/UaaTokenEndpoint.java` still reads:

> `MtlsClaimsEnhancer` trusts that any `resource` value surviving to token issuance was already
> validated here — this is the only path into the granter for `/oauth/mtls/token`, so that invariant
> holds without a second, redundant allow-list check at claim-enhancement time.

That is precisely the reasoning `pr4076-security-review.md` §1 recorded as **wrong** (Spring also
mapped `/oauth/mtls/token/oauth/token` to the inherited handler), and `MtlsClaimsEnhancer` now
carries a comment saying the opposite and does re-check the allow-list. A future maintainer reading
only this javadoc has an explicit invitation to delete the enhancer's check as "redundant".

**Action:** rewrite the paragraph to say the enhancer re-checks deliberately, and why.

### L2 — `MtlsClaimsEnhancer` casts the loaded client unguarded, and its comment claims handling that is absent

**Severity: low.**

`MtlsClaimsEnhancer.enhance` does
`UaaClientDetails clientDetails = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId);`
with no `instanceof` and no `try`. A few lines later a comment refers to "the client-details lookup
failure above" following a "fail-closed philosophy" — there is no such handling above; a
`NoSuchClientException` or any other `ClientDetails` implementation becomes a 500 out of token
issuance. `UaaTokenEndpoint.allowedResourcesFor` does the same lookup *defensively*
(`client instanceof UaaClientDetails`, `catch (Exception e) { return List.of(); }`), so the two
call sites disagree about whether this lookup can fail.

Unreachable in practice (the client authenticated moments earlier, and UAA's JDBC service returns
`UaaClientDetails`), so this is consistency and comment accuracy, not a live defect.

### L3 — `UaaClientDetails.tlsClientAuthConfiguration`: dead in production, wrong comment, serialization landmine

**Severity: low.**

Three separate small problems in one field:

- **Never set by production code.** The only caller of `setTlsClientAuthConfiguration` in `main/` is
  `UaaClientDetails`'s own copy constructor, which copies it from a prototype that itself can only
  have got it from a setter nobody calls. So the "check the typed field first (set directly on
  in-memory / admin-API clients)" fast path in both `MtlsClaimsEnhancer` and
  `UaaTokenEndpoint.allowedResourcesFor` is **always** a miss in production, and the comment
  describing it is wrong. The `additionalInformation` fallback is the only live path.
- **Serialization.** `UaaClientDetails implements ClientDetails extends Serializable`
  (`model/.../oauth/provider/ClientDetails.java:18`), the field is **not** `transient`, and
  `TlsClientAuthConfiguration` does **not** implement `Serializable`. Harmless only because of the
  point above; it becomes a `NotSerializableException` the day anyone sets it. Note that the
  neighbouring `additionalInformation` field *is* `transient`, so the class is already serialized in
  practice somewhere.
- **`equals`/`hashCode`.** The field now participates in both, while being derived from
  `additionalInformation`. A DB-loaded client and a setter-built client with identical configuration
  compare unequal.

**Action:** either make the field `transient` and drop it from `equals`/`hashCode` (keeping it as a
pure in-request cache), or populate it on the JDBC load path so the fast path is real. Doing neither
leaves two comments in the tree that describe behaviour that does not exist.

### L4 — the claim-mapping `pattern` has no complexity bound, while templates do

**Severity: low / informational.**

`ClientAdminEndpointsValidator` bounds `tls-client-auth-sub-template` /
`-aud-templates` at `MAX_TEMPLATE_LENGTH = 256` specifically to cap regex work on operator data, and
mirrors the bound in `MtlsClaimsEnhancer` for the bootstrap path. `tls-client-auth-claim-mappings`
`pattern` gets neither bound: it is compile-checked and required to have a capturing group, but a
syntactically valid catastrophic-backtracking pattern (`(a+)+b`) is accepted and then
`Pattern.compile`d and matched against certificate OU values on **every token request**
(`TlsClientAuthentication.matchFirstOu`). Operator-supplied, so this is an availability footgun
rather than an attack surface — but it is inconsistent with the bound deliberately added next to it.

## 3. Independently re-verified, no issue found

Recorded so the next reviewer does not redo it:

- **The disabled path is inert.** `/oauth/mtls/token` 404s at `MtlsEndpointAvailabilityFilter`
  (order -290, after zone-path rewriting at `HIGHEST_PRECEDENCE+1`, before Spring Security at -100),
  in both zone-addressing modes, and so does everything below it. `RawPeerCertificateCaptureFilter`
  is ungated but only copies one attribute for paths that 404. Green:
  `MtlsDisabledTokenEndpointMockMvcTests`, `MtlsFlagConsistencyMockMvcTests`.
- **No earlier OAuth filter chain claims the path.** `tokenEndpointSecurity` matches
  `/oauth/token/**`, which does not match `/oauth/mtls/token`; the new chain at `OAUTH_11` is
  reachable. (`OAUTH_11` = 211 sorts after `OAUTH_10` = 210, which matters only against
  `oauthAuthorizeRequestMatcherOld`, a disjoint matcher.)
- **`MtlsEnabledCondition` genuinely unifies the two readings of the flag.** Reading via
  `Environment.getProperty(key, Boolean.class, false)` goes through the same conversion service as a
  `boolean` `@Value` injection point, so `1`/`yes`/`on` can no longer half-enable the feature.
- **The new dependency does not self-register.** `java-buildpack-client-certificate-mapper-jakarta`
  contributes neither an `AutoConfiguration.imports`/`spring.factories` entry nor a
  `ServletContainerInitializer` SPI entry, and
  `ClientCertificateMapperAutoConfigurationExclusionTest` fails the build if a future bump adds
  either. With the flag off the class is never even loaded (the registration bean is
  `setEnabled(false)` and construction is skipped), so a deployment that will never enable mTLS does
  not depend on that jar to boot.
- **External OAuth/OIDC is explicitly excluded** from `tls_client_auth`:
  `ClientAuthentication.EXTERNAL_OAUTH_SUPPORTED_METHODS` keeps the old four-method list, both the
  IdP config validator and the BOSH IdP factory bean switch to it, and
  `ExternalOAuthAuthenticationManager` throws on `tls_client_auth` at both token-request sites. The
  widened `UAA_SUPPORTED_METHODS` therefore does not leak into relying-party configuration.
- **`InvalidTargetException` returns 400, not 401** — `ClientAuthenticationException.getHttpErrorCode()`
  is 400, which is what RFC 8707 calls for.
- **`ZoneEndpointsClientDetailsValidator`'s relaxed secret requirement cannot fire with the flag
  off** (`checkMtlsClientConfigAllowed` throws first), and `clientSecretValidator.validate(null)`
  returns early, so the mTLS-with-no-secret zone-client path does not trip the secret policy.
- **The three new container-level filters use the same registration mechanism as every pre-existing
  UAA filter** (`FilterRegistrationBean` in `SpringServletXmlFiltersConfiguration`, as
  `IdentityZoneResolvingFilter`, `CorsFilter`, `UaaMetricsFilter` et al. already do), and the only
  published artifact is the executable `bootWar` (`uaa/build.gradle.kts`: the plain `war` task is
  `isEnabled = false`). So the feature inherits the deployment topology of the rest of the server
  rather than introducing a second one. No new exposure here — this was checked precisely because a
  Boot-only registration would have meant the 404 guarantee did not exist on an
  external-container deployment.

## 4. Already recorded elsewhere — re-confirmed, not re-litigated

- `ClientDetailsAuthenticationProvider`'s mTLS branch has no flag gate, so a client row carrying
  `tls-client-auth-ca` written while the feature was on becomes inert (not insecure) after an
  operator turns it off — flag audit §2, test **E8**. Re-read the code; agrees.
- The RFC 8705 §2.1.2 subject-binding requirement is knowingly incompatible with the config shape
  PR #3972 allowed — compatibility audit §3. It is the security fix at the heart of the branch.
- `cnf` copied forward on refresh (security review §3.1), `act` not reserved (§3.2), template
  delimiter collision (§3.3), no revocation checking (`rfc8705-feature-gaps.md`) — all unchanged,
  all still open product decisions, none newly reachable.

## 5. What an operator still needs told, beyond the code

Not defects — consequences of enabling the feature that the merge decision should be made with eyes
open about. The first is documented in `docs/UAA-Client-Authentication.md`; the other two are not
documented anywhere outside `SESSION-HANDOFF.md` §9.

1. **The TLS-layer change is connector-wide, not endpoint-scoped.** `uaa.mtls-enabled=true` puts the
   whole embedded connector on the FIPS BouncyCastle JSSE provider, sets
   `certificateVerification=optionalNoCA`, and advertises an empty acceptable-issuer list — so
   *every* TLS handshake to that UAA instance, browsers included, now carries a `CertificateRequest`
   with no CA constraint, and cipher/protocol negotiation for all traffic moves from SunJSSE to
   BCJSSE. Well-behaved clients send an empty `Certificate` message, which is why this does not break
   other endpoints, but the blast radius of the switch is the whole listener. Interop and performance
   on the BCJSSE stack are the things to soak-test before enabling on a live foundation, and they are
   the one part of this feature no test in the repo can cover.
2. **There is no per-zone enablement.** The flag is global: enabling it advertises `tls_client_auth`
   in every zone's discovery document and lets any zone admin register a `tls-client-auth-ca`.
3. **`/oauth/mtls/token` has no dedicated rate-limiter mapping** and sits in the default global
   bucket, while being the most CPU-expensive token path in UAA (PKIX validation per request).

## 6. Bottom line

Nothing found in this pass blocks the merge on security or on gating grounds: the feature is off by
default and genuinely inert when off, and when on it is the hardened shape this branch was written
to produce.

What should not merge silently is **M1** — a change to the claims of refresh-issued access tokens on
every deployment that registers a token enhancer, currently undocumented in the PR and in the compatibility
audit — and **M2**, an
upgrade-time session-deserialization break that is one keyword away from being fixed. Both are
independent of the feature flag, which is exactly why they need to be stated rather than carried in
on the feature's coat-tails.
