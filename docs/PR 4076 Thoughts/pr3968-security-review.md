# Security review — PR #3968, SPIFFE JWT-SVID signing endpoint

Reviewed: `review/pr3968` (9 rkoster commits squashed to `aaed536f7`), rebased on
`cloudfoundry/develop` at `d6db8c71e`. Scope: the 12 production classes under
`server/src/main/java/org/cloudfoundry/identity/uaa/spiffe/` and their integration into UAA's
filter chain, configuration, and token-signing machinery.

Conformance was checked against the
[SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) and
[JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) specifications.

## Summary

The core design is sound, and one part of it is notably good: separating the **caller** (the SPIFFE
Agent, authenticated by ordinary client credentials) from the **subject** (the workload, attested by
certificate plus proof of possession) means the agent's own credentials never authorize minting a
particular identity. That is what makes a single shared agent client safe, and it is the right
answer to the problem RFC 8705 could not express.

Six issues were found and fixed. Twelve more are recorded below as decisions for the author,
mostly because they are wire-protocol or product choices rather than defects.

## Fixed in `c2361dff1`

### 1. HIGH — SPIFFE ID injection via certificate OU attributes

`process_type` was validated against `[A-Za-z0-9_-]{1,63}` specifically because it is concatenated
into the SPIFFE ID path — the final commit's own message says so. But `org`, `space` and `app` land
in the *same* path and were interpolated unchecked, straight from certificate OU attributes.

Confirmed by test, HTTP 200: a certificate bearing `OU=app:a/process/admin` produced

```text
spiffe://cf.example.com/cf/org/o/space/s/app/a/process/admin/process/web
```

A relying party authorizing on a path prefix is given a different workload's identity. The same gap
admitted newlines, which is the PoP-message ambiguity the commit claimed to close.

Exploitability caveat: this requires the Diego CA to have issued a certificate with a crafted OU,
so in a correctly-operating foundation it is defense-in-depth against a misbehaving issuer or a
misconfigured CA rather than a directly reachable attack. SPIFFE ID conformance is mandatory
regardless — the spec's character rule exists precisely to make path-prefix authorization safe.

`SpiffeId` now enforces `[a-zA-Z0-9.-_]` per segment, rejects `.` and `..`, and caps the ID at the
specified 2048 bytes. Segment errors do not echo the certificate-supplied value.

### 2. MEDIUM — the trust anchor was usable as a workload identity

A self-signed certificate verifies against its own public key, so checking only "signed by the CA
key" accepted the configured CA certificate as though the CA had issued it as a leaf. It was
refused only incidentally, for lacking CF OUs (400, not 401). The CA certificate is public
configuration. The CA's own validity dates were also never checked, so an expired trust anchor kept
anchoring trust.

Now rejects self-issued and CA-flagged certificates outright, and checks CA validity.

### 3. MEDIUM (blast radius: the whole application) — application-wide `@ControllerAdvice`

`JwtSvidController.ExceptionHandling` was unscoped. `@ControllerAdvice` is meta-annotated
`@Component`, and the nested class carried no `@ConditionalOnProperty` of its own — only the outer
controller did. Under `@ComponentScan("org.cloudfoundry.identity.uaa")` it therefore registered
**even with the SPIFFE feature switched off**, mapping any `IllegalArgumentException` thrown
anywhere in UAA to a 400 whose body is the raw exception message.

That is both an information-disclosure vector and an unintended status-code change across every
endpoint in the product. The only other advice in the codebase, `HttpMethodNotSupportedAdvice`, is
correctly scoped with `assignableTypes`; this one now matches.

### 4. MEDIUM — unset trust domain issued `spiffe://null/` identities

Only `instance_identity_ca` gates the feature on, so `trust_domain` could be omitted entirely and
every workload on the foundation would receive an identity under `spiffe://null/`, surfacing only
at a relying party. Now validated at startup (non-empty, ≤255 chars, lowercase `[a-z0-9.-_]`) and a
boot failure if wrong.

### 5. LOW/MEDIUM — duplicate OU attributes resolved by RDN ordering

Two OUs sharing a prefix silently let the last one win, so a certificate carrying both `app:real`
and `app:other` resolved to whichever the encoder happened to place last. Now refused.

### 6. LOW — misleading diagnostics

The startup exception named `uaa.spiffe.instance_identity_ca`, which is a valid spelling in
`uaa.yml` but not the canonical form. Corrected, and UAA now logs a loud warning when
`pop_enabled` is false.

## Recorded for the author — not changed

### 7. HIGH, but config-dependent — `pop_enabled: false` is a total impersonation bypass

With PoP disabled, `ProofOfPossessionVerifier.isValid` returns `true` unconditionally. Any client
holding `uaa.resource` can then obtain a JWT-SVID for **any** workload on the foundation merely by
presenting that workload's certificate — which is not a secret; it is sent in TLS handshakes and
forwarded by Gorouter in `X-Forwarded-Client-Cert`.

Default is `true`, and a startup warning was added. Recommendation: consider deleting the flag, or
gating it behind a development-only profile. A switch whose only effect is "turn off the single
control that makes this endpoint safe" is worth not shipping.

### 8. MEDIUM — no replay protection inside the freshness window

The PoP message binds the SPIFFE ID, audience and timestamp, but nothing tracks nonces or `jti`
values. A captured `pop_signature` may be replayed for as long as its timestamp stays within
`pop_freshness_seconds` (±60s by default, since the comparison is on absolute difference), and each
replay yields a fresh token valid for the full TTL — one hour by default. Fixing this needs a
short-lived nonce store, which is an architectural addition rather than a patch.

### 9. MEDIUM — the PoP message has no domain separation

The signed message is `spiffeId \n audience \n timestamp` with no protocol label. If a workload
ever signs structurally similar data for another purpose with the same key, cross-protocol
signature reuse becomes possible. The fix is cheap — prefix a constant such as
`uaa-jwt-svid-pop-v1` — but it is a wire-protocol change that must land together with the agent
implementation, so it is not mine to make unilaterally. Pre-merge is the cheapest time to do it.

### 10. MEDIUM — JWT-SVIDs are cryptographically indistinguishable from UAA access tokens

An SVID is signed with `keyInfoService.getActiveKey()` — the same key as access tokens — with the
same `iss`, and a header carrying the same `typ: JWT`, `alg` and `kid`. Only the claim set
separates the two token populations.

UAA's own introspection does reject an SVID, because `JwtTokenSignedByThisUAA.checkClient` requires
`cid`/`client_id` and an SVID has neither (verified in test F2). But that is incidental rather than
designed, and it offers nothing to an external relying party doing naive "verify signature + iss"
validation. RFC 8725 §3.11 recommends distinct keys for distinct purposes. Recommendation: a
dedicated SVID signing key, or an explicit token-type claim. Test group F pins the current
separation so it cannot erode silently.

### 11. MEDIUM — `uaa.resource` is too broad a gate

The endpoint requires `uaa.resource`, an authority shared by every resource server that calls
`/introspect` or `/check_token`. A dedicated authority (`spiffe.sign` or similar) would follow least
privilege. This is a compatibility-affecting product decision.

### 12. LOW/MEDIUM — default token lifetime is long for a bearer credential

`jwt_svid_ttl_seconds` defaults to 3600. The JWT-SVID spec recommends "an aggressive value for the
`exp` claim" because these are bearer tokens; SPIRE's own default is 300 seconds. There is also no
bounds validation on the configured value. Documented; the default is the author's call.

### 13. LOW — no audit events

The endpoint mints a credential and produces no audit record, so there is no trail of which agent
obtained which workload's identity, when. UAA has an audit-event framework this does not use.

### 14. LOW — identity-zone semantics are unconsidered

`uaa.spiffe.*` is global, but `JwtSvidSigner` takes the issuer from `IdentityZoneHolder.get()` and
the endpoint is reachable in any zone. So the same trust domain is served across zones under
differing issuers. Differing `iss` limits the practical impact, but the intended zone semantics
should be stated — most likely restricting the endpoint to the default zone.

### 15. LOW — signature check rather than PKIX path validation

`InstanceIdentityVerifier` does a raw signature check. There is no `keyUsage`/`extendedKeyUsage`
enforcement, no critical-extension processing, and no revocation checking (no CRL or OCSP) — the
same accepted gap as the mTLS work, and defensible for short-lived Diego certs. Note also that
`KeyWithCert` reads only the first PEM object, so only leaves signed **directly** by the configured
CA work; an intermediate-issued chain cannot be presented. Now documented.

### 16. LOW — error responses contradict the declared content type

The endpoint declares `produces = "application/json"` but `ExceptionHandling` returns
`ResponseEntity<String>` bodies, so failures are plain text. Those bodies also relay certificate
verification exception messages to the caller.

### 17. LOW — no `Cache-Control: no-store`

The response carries a credential and sets no cache directives.

### 18. INFO — rate limiting

`/jwt-svid/sign` has no dedicated limiter mapping, so it falls into the default global 1000r/s
bucket. Both PoP verification and JWT signing are CPU-bound. A dedicated mapping would be prudent.

## Investigated and found NOT to be problems

- **Config key spelling.** I expected `instance_identity_ca` (snake_case — which the code's own
  javadoc recommends, and UAA's house style in `uaa.yml`) to satisfy `@ConfigurationProperties`
  relaxed binding but *not* `@ConditionalOnProperty`'s exact key lookup, silently leaving the
  feature disabled. **Tested empirically: both spellings activate the feature**, because Spring Boot
  attaches a relaxed-binding property source to the `Environment` that `@ConditionalOnProperty`
  resolves through. Not an issue — and worth recording, since it is a plausible-sounding bug that
  isn't real.
- **Null `instance_certificate`** → 400, not 500. The NPE inside `KeyWithCert`'s try-with-resources
  is caught and wrapped as `CertificateException`. Fail-closed.
- **Missing `timestamp`** → the primitive `long` defaults to 0, which is outside any sane freshness
  window, so PoP fails. Fail-closed.
- **Unsupported certificate key type** → `algorithmFor` throws inside the `try`, so PoP returns
  false rather than propagating. Fail-closed.
- **Single-valued `aud`** matches the spec's "strongly recommended" single audience. The JWT encoder
  collapses the one-element list to a scalar string, which RFC 7519 §4.1.3 permits.

## Verification

- 23 new end-to-end MockMvc tests over the real filter chain: pass.
- Server SPIFFE unit tests 35 → 80: pass.
- Full unit suite: 8441 tests, 0 failures (`BUILD SUCCESSFUL`, exit 0).
- `generateDocs`: succeeds; rendered HTML contains the section, nav entry and field tables.
- `integrationTest`: 371/376, the single failure being the pre-existing
  `ScimGroupEndpointsIntegrationTests.deleteNonExistentGroupFailsCorrectly` SCIM rate-limiter 429
  flake — unrelated to this work (SPIFFE is disabled in that environment), also seen on
  `review/pr3792-fix`, and passing 18/18 when that class runs in isolation.
