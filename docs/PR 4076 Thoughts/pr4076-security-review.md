# Security review — PR #4076, the mTLS feature as it now stands

Reviewed on `review/pr3792-fix` at `ec02e642e` (the RFC 8707 work had just landed and had never been
reviewed by anyone). Three independent reviewers were run over separate slices so they could not
converge on each other's assumptions:

1. the RFC 8707 resource-indicator surface,
2. the certificate-authentication and trust decision,
3. token claims, client registration and multi-tenancy.

Two of the three independently reported the same highest-severity finding, and it was then confirmed
by test before anything was changed. Everything below labelled "confirmed" was reproduced; anything
inferred from reading alone is labelled as such.

## 1. HIGH — both endpoint guards were bypassable one path segment deeper

**Confirmed by test, then fixed.** `147929d23` (red) → `117a8c436` (green).

`UaaTokenEndpoint` carries a type-level `@RequestMapping({"/oauth/token", "/oauth/mtls/token"})` and
extends `TokenEndpoint`, whose inherited `getAccessToken`/`postAccessToken` carry their own
`@GetMapping("/oauth/token")`/`@PostMapping("/oauth/token")`. Spring MVC registers inherited handler
methods and combines them with the subclass's type-level patterns, so **`/oauth/mtls/token/oauth/token`
was a live mapping** — and being literal it outranked `UaaTokenEndpoint`'s own `"**"` delegates.

Both endpoint-level guards are called from those delegates, so neither ran on that URL. Everything
else about the request still behaved as mTLS, because the filters, the security matcher and
`isTlsClientAuthPath` all match descendants by prefix: the certificate authenticated normally and
`MtlsClaimsEnhancer` stamped the token as usual.

Observed, both HTTP 200:

| Probe | Result before the fix |
|---|---|
| `resource=` a value **not** in `tls-client-auth-allowed-resources` | token issued with `aud` set to exactly that value |
| `grant_type=password` | one token carrying `cnf.x5t#S256` **and** `user_id`/`user_name`/`email`/`auth_time` |

The second matters beyond the new work: it re-opened
`rejectNonWorkloadGrantAtMtlsEndpoint`, which is fix #3 in `pr3972-vs-pr3792-fix-comparison.md`. So
this was not only a gap in the RFC 8707 addition — it defeated a control this branch already claimed.

Also worth noting: clients with **no** allow-list configured were affected too, which is the case the
canonical path refuses outright.

### How it was fixed

Two independent fixes, because the first alone would leave the guarantee dependent on Spring's
handler ranking:

1. **`MtlsEndpointAvailabilityFilter` answers 404 for any path below the endpoint**, before Spring
   Security and before any handler. The endpoint is exactly one path; a descendant is not a variant
   spelling of it but a different resource that does not exist. This removes the whole class of
   routing bypass rather than the two known symptoms — any handler Spring maps under the prefix, now
   or later, is unreachable. Nothing legitimate lived below it: the alias sub-paths under
   `/oauth/token` exist for SAML bearer grants, which this endpoint does not issue.

   `isMtlsTokenPath` keeps its prefix semantics deliberately. The capture filter, the mapper guard
   and `isTlsClientAuthPath` must keep matching descendants, or a request that slipped past would be
   treated as non-mTLS and silently lose its raw-peer certificate instead of being refused. Two
   existing unit tests pin that prefix behaviour.

2. **`MtlsClaimsEnhancer` no longer trusts the endpoint** to have validated `resource` — that
   assumption is exactly what failed — and re-checks it against the allow-list itself, failing the
   token request rather than falling back to a default audience the caller could not distinguish
   from the one it asked for. It also refuses a `resource` on any grant other than
   `client_credentials`.

   This required `loadTlsConfig` to parse `tls-client-auth-allowed-resources`, which it did not.
   Without that, `getAllowedResources()` is null for every JDBC-loaded client — i.e. almost every
   real one — so a fail-closed check would have refused resources the operator did permit. Test H5
   (an allow-listed resource still becomes `aud`) is what proves the parsing works rather than
   silently denying everything.

## 2. LOW, latent — the client-auth gate read a different path than every other gate

**Confirmed at unit level, then fixed.** `04c510e31` (red) → `2874f28d9` (green).

Every mTLS gate keys off `HttpServletRequest.getServletPath()`, which the container has already
decoded and normalised. `ClientDetailsAuthenticationProvider.isTlsClientAuthPath` instead keyed off
`UaaAuthenticationDetails.getRequestPath()`, built from `getRequestURI()` — raw and undecoded per the
servlet spec. For `/oauth/%6dtls/token` the two disagree: Tomcat decodes `%6d` to `m`, so everything
else treats the request as the mTLS endpoint while that gate concluded it was not, disabling the
check whose own javadoc reads *"Without this check the endpoint is an unrestricted alias of
/oauth/token"*.

**Impact was traced, not assumed, and is narrower than it first looks.** An ordinary secret client
could authenticate at the encoded spelling, but the token it received is what `/oauth/token` would
have issued: `MtlsClaimsEnhancer` adds no `cnf`, because `client_auth_method` is not
`tls_client_auth`, and the grant and resource guards still fire because they use the servlet path. An
mTLS-configured client is refused there. So this was a broken invariant and a latent hazard rather
than a live escalation — fixed because the next gate to depend on the wrong path source may not be so
lucky.

`UaaAuthenticationDetails` now also carries the decoded servlet path, *alongside* `requestPath`
rather than replacing it (audit consumers and `isPublicTokenRequest` expect the raw form), and the
gate answers true when either reading resolves to the endpoint — the fail-closed direction, since a
true only ever adds restrictions.

**Verification note:** MockMvc cannot reproduce this end to end. It asserts that the request URI
decomposes into contextPath + servletPath, so it refuses to build a request whose two path views
disagree — the same constraint recorded in `SESSION-HANDOFF.md` §8. The divergence is therefore
pinned at the unit level, where the defect actually lives, and the end-to-end consequence above is
from reading the call chain.

## 3. Recorded, not fixed

### 3.1 `cnf` is copied forward on token refresh without re-checking the certificate

`UaaTokenServices.refreshAccessToken` builds `additionalRootClaims` from the refresh token's claims
via `getAdditionalRootClaims`, which filters `NON_ADDITIONAL_ROOT_CLAIMS` — and **`cnf` is not in that
set** (verified). So a refresh token carrying `cnf` yields a new access token that is
certificate-bound to a certificate the presenter never demonstrated possession of on that call.

Reachability: a `cnf`-bearing refresh token can only exist if a refresh-issuing grant ran while the
enhancer was stamping `cnf`. At `/oauth/mtls/token` only `client_credentials` is reachable, and it
never issues a refresh token — so this was reachable **only** through finding 1, and is unreachable
now that finding 1 is fixed.

It is still a fail-open shape rather than a fail-closed one, so it is worth a deliberate decision
rather than leaving it to luck. Two options: add `cnf` to `NON_ADDITIONAL_ROOT_CLAIMS` so a refreshed
token is honestly unbound, or refuse the refresh outright when the refresh token carries `cnf` and no
matching certificate is presented. The second is the RFC 8705 §7.1 shape; the first is one line.
Left as a product decision because it changes refresh semantics.

### 3.2 `act` is not a reserved claim name

`TlsClientAuthConfiguration.RESERVED_CLAIM_NAMES` does not include `act` (RFC 8693 actor), so a
`tls-client-auth-claim-mappings` entry may target `act` or `act.sub`. UAA never reads `act` for an
authorization decision, so no exploit was demonstrated. Worth adding to the reserved set on the same
reasoning that put `amr`/`acr`/`cnf` there: a certificate subject field should not be able to assert
delegation semantics a downstream consumer might honour.

### 3.3 Template delimiter collision

A certificate value containing a template's own delimiter (e.g. a value containing `/s/` inside
`o/{cf.org}/s/{cf.space}`) shifts the meaning of the rendered claim for a consumer doing prefix
matching. With subject binding enforced, no case was found where an attacker controls such a value,
so it is recorded rather than rated.

## 4. Verified clean

The negative results are the more useful half of this review, because several are exactly the
plausible-sounding findings that would otherwise be re-litigated every round.

**RFC 8707 surface**

- **Parameter smuggling between the two views of the request.** `enforceResourceIndicator` validates
  `request.getParameterValues("resource")` while the enhancer reads
  `OAuth2Request.getRequestParameters()`. Traced: `@RequestParam Map<String,String>` is resolved by
  `RequestParamMapMethodArgumentResolver`, which takes `values[0]` of the *same array*
  `getParameterValues` returns, and `createTokenRequest`/`createOAuth2Request` pass `resource`
  through unmodified. The validated string and the projected string are the same object. Duplicates
  across query string and body give `length > 1` and are rejected.
- `allowedResourcesFor` fails closed on every branch — client-load exception, non-JSON string, JSON
  that is not an array — all return an empty list, which permits nothing.
- The allow-list comparison is exact equality on a value already syntax-checked, with no
  normalisation step between validation and projection.
- All three client-creation paths validate the new key: the admin API, `ClientAdminBootstrap`, and
  `ZoneEndpointsClientDetailsValidator` all call `validateTlsClientAuthClaimConfig`.
- No UAA-internal privilege escalation from a forged `aud`: UAA's own resource-server gate only
  *restricts* (it requires `aud` to contain the resource id) and authorization still comes from
  `scope`/`authorities`, which the enhancer cannot touch. `/check_token` and `/introspect` report
  `aud` but do not authorize on it. The impact of finding 1 was therefore scoped to downstream
  RFC 8705/8707 resource servers.

**Certificate authentication**

- **Subject matching.** DN comparison canonicalises both sides through `LdapName`: RDN order is
  significant, RDN count must match, multi-valued AVAs are sorted before comparison, and escaped
  commas/quotes and `#`-hex DER values normalise identically because the certificate side is
  rendered with `X500Principal.RFC2253` and re-parsed. SAN matching enforces the `GeneralName` tag
  (a dNSName binding cannot be satisfied by an email SAN reading the same), iterates **all** SANs of
  the right type, and has no wildcard, prefix or suffix path.
- **Chain validation.** Stock `PKIXParameters`, so validity dates, `basicConstraints`/pathLen,
  `keyCertSign` and name constraints are enforced by the JDK; `validateEndEntityConstraints` then
  rejects a CA-flagged leaf, a leaf whose KU excludes `digitalSignature`, or an EKU that excludes
  `clientAuth`. The certificate matched against the subject binding is `chain[0]` — the same one
  PKIX treats as the leaf and the same one the TLS `CertificateVerify` proves possession of — so
  appending attacker-chosen certificates cannot change which certificate is matched. One
  `TrustAnchor` per bundle entry widens the anchor set intentionally, for rotation, and exploiting it
  requires the corresponding private key.
- **XFCC / proxy topology.** The buildpack mapper jar was decompiled: it reads all
  `X-Forwarded-Client-Cert` values and overwrites the standard attribute only on success, and it
  ships no `ServletContainerInitializer` and no autoconfiguration import, so it cannot self-register
  ahead of the capture filter. Direct-topology clients read only the raw handshake attribute, so a
  forged XFCC header is ignored. Proxy-topology clients require the header, require the genuine peer
  to validate against the proxy CA, and require the forwarded chain to differ from the raw peer chain
  — which closes the case where a mapper parse failure would leave the proxy's own certificate
  standing in as the client's.
- **Zone isolation.** Client lookup resolves through `identityZoneManager.getCurrentIdentityZoneId()`
  on every path checked (client auth, the enhancer, `allowedResourcesFor`). The certificate
  contributes nothing to client resolution, so a cert/client pair in one zone cannot authenticate in
  another.
- **Fail-open walk.** Every `catch`, null check and boolean helper in `TlsClientAuthentication` and
  `TlsClientAuthSubjectMatcher` was walked; all failure outcomes deny. No fail-open branch found.

**Claims, registration, multi-tenancy**

- `RESERVED_CLAIM_NAMES` covers what `UaaTokenServices` protects plus the reachable authentication-
  context set; `isReservedClaimName`'s root-segment check is the right shape for the enhancer's
  single-level dot nesting, so `sub.foo`/`cnf.x` cannot produce an object-valued `sub`/`aud`. `cnf`
  is written after all mappings and cannot be suppressed or overwritten by a client admin.
- Template rendering cannot be escaped: `appendReplacement` scans the template, never the substituted
  output, so a certificate value containing `{`/`}` cannot trigger a second substitution round, and
  `quoteReplacement` closes the `$`/`\` route. An unresolved placeholder drops the whole template.
- Regex capture is full-string (`matches()`), requires a capturing group, and `pattern` is refused on
  the fields where it would be ignored.
- Claim-assembly failure aborts the token request — the enhancer loop in `UaaTokenServices` has no
  `try`/`catch`, and the `cnf` computation throws rather than issue an unbound token.
- Certificate revocation is disabled deliberately (`setRevocationEnabled(false)`) and documented in
  `docs/UAA-Client-Authentication.md`; it was excluded from this review as a known accepted decision.

## 5. Verification

- Full unit suite: **green** (see `SESSION-HANDOFF.md` §6 for current counts).
- `./gradlew generateDocs`: **success**, and the rendered `index.html` carries the mTLS section
  including the `resource` parameter.
- The two findings above were each pinned by a red test before the fix and are now green:
  group I (`I1`, `I2`) in `MtlsTokenEndpointHardeningMockMvcTests`, four new cases in
  `MtlsClaimsEnhancerTest` that exercise the enhancer with the endpoint check absent, and
  `tlsClientAuthPathFollowsTheDecodedServletPathNotTheRawUri` in
  `ClientDetailsAuthenticationProviderTests`.
- Group I also closes the descendant-path coverage gap that `SESSION-HANDOFF.md` §9 had recorded as
  outstanding.
