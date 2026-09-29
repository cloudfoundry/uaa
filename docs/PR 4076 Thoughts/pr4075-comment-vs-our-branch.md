# rkoster's #4075 review response vs. `review/pr3792-fix`

Comment evaluated:
[#4075 (comment) of 2026-09-24](https://github.com/cloudfoundry/uaa/pull/4075#issuecomment-5816089590)

## The thing to know first: the branches have diverged

The comment says 14 follow-up commits were pushed to
[#3972](https://github.com/cloudfoundry/uaa/pull/3972), `471ad5780` → `a80e1c94f`.

`471ad5780` is precisely the last of the 132 commits squashed into the base of
`review/pr3792-fix`. So **none of those 14 commits are on our branch**, confirmed:

```text
git merge-base --is-ancestor a80e1c94f HEAD   ->  absent
```

PR #3972 is now at 146 commits (our 132 + his 14) on `rkoster:feat/rfc8705-mtls-client-auth`.

The consequence: **both branches independently fixed most of the same findings, in different
ways.** That is why the `FINDING` / `FAILS TODAY` markers on our branch had gone stale — our own
later commits fixed them, not his. Neither branch is a superset of the other, and they cannot simply
be merged without reconciling two implementations of the same fixes.

His 14 commits:

```text
433728d0d fix(review): return authentication errors for invalid mTLS certificates
8741802c6 fix(review): protect reserved roots in mTLS claim mappings
6f3988eb9 fix(review): return 404 for disabled mTLS token endpoint
e4ca968c6 fix(review): require certificate authentication at mTLS endpoint
b3c51f6f8 fix(review): preserve inert client authentication metadata
38357eb14 fix(review): restrict mTLS token endpoint to workload grants
343cf6198 fix(review): require certificate-derived subject templates
cb5fbd889 fix(review): skip certificate mapper construction when mTLS is disabled
09f1992dd refactor(review): share mTLS client configuration parsing
ede683ee4 feat(review): support mTLS CA rotation with trust bundles
1cc3ed46e docs(review): clarify mTLS certificate revocation behavior
067fac040 refactor(review): replace test-only client auth helper with grant coverage
aa075f583 fix(review): require POST for mTLS token requests
a80e1c94f fix(review): distinguish mTLS certificate and claim failures
```

## Findings both branches have addressed

Each of these was verified on our branch by running the tests and reading the actual responses, not
inferred from a green suite.

| Finding from the review | His fix | Ours — verified behaviour |
|---|---|---|
| mTLS endpoint served every grant type, incl. `password` / `refresh_token` | `38357eb14` | `400 invalid_grant`, "the mTLS token endpoint only issues client_credentials tokens" |
| Same validation failure returned 500 + stack trace depending on which client-auth filter ran | `433728d0d` | Clean `401 invalid_client` with the chain-validation message, identical for Basic and parameter auth |
| `/oauth/mtls/token` was an unrestricted alias of `/oauth/token` | `e4ca968c6` | `401 invalid_client`, "/oauth/mtls/token requires a client configured with tls-client-auth-ca" |
| `tls-client-auth-sub-template` with no placeholder forged an arbitrary `sub` | `343cf6198` | `400 invalid_client`, "must contain at least one {claim} placeholder" |
| Claim mappings could set `amr` / `acr` | `8741802c6` | `400 invalid_client`, "maps onto reserved claim 'amr'" — and **dotted mappings are handled**: `isReservedClaimName` checks the root segment, so `acr.level` is caught too |
| With `uaa.mtls-enabled=false` the endpoint still resolved | `6f3988eb9` | `404` from `MtlsEndpointAvailabilityFilter`, before browser security |
| `token-endpoint-auth-method` rejection broke unrelated clients | `b3c51f6f8` | Accepted as inert metadata; client creation returns `201` |

Both branches also independently implement `tls-client-auth-required-claims`
(ours enforced in `TlsClientAuthentication:267`).

## What his branch fixed and ours has not

Ranked by how much they matter.

### 1. CA trust-bundle rotation — functional gap (`ede683ee4`)

Ours parses **one** certificate:

```java
// TlsClientAuthentication.parsePemCertificate
try (PEMParser parser = new PEMParser(new StringReader(pem))) {
    Object obj = parser.readObject();   // first PEM object only
```

and builds a single anchor: `new TrustAnchor(caCert, null)`.

So a `tls-client-auth-ca` holding an old+new overlap bundle silently uses only the first entry.
**An operator cannot rotate the Diego instance-identity CA without breaking authentication**, which
for short-lived platform CAs is a real operational problem rather than a nicety. His version parses
every entry, treats each as an anchor, and rejects the whole bundle if any entry is malformed
(fail-closed, which is the right choice). This applies to `tls-client-auth-trusted-proxy-ca` as
well, which our code parses the same single-cert way.

### 2. mTLS endpoint is not POST-only (`aa075f583`)

`UaaTokenEndpoint` maps both paths together:

```java
@RequestMapping(value = {"/oauth/token", "/oauth/mtls/token"})
...
@GetMapping("**")
super.setAllowedRequestMethods(new HashSet<>(Arrays.asList(HttpMethod.GET, HttpMethod.POST)));
```

so `/oauth/mtls/token` inherits `/oauth/token`'s GET support. A GET token request puts parameters in
the query string, where they land in access logs and proxy logs. His fix returns `405` with
`Allow: POST`. Worth taking.

### 3. Mapper is constructed even when mTLS is disabled, and its absence fails boot (`cb5fbd889`)

`clientCertificateMapperFilter()` has no `@ConditionalOnProperty`, reflectively instantiates the
buildpack `ClientCertificateMapper` unconditionally, and on failure throws:

```java
throw new IllegalStateException("Failed to instantiate ClientCertificateMapper", e);
```

Two consequences: the filter is built on deployments that never enabled mTLS, and if the buildpack
jar is ever absent from the classpath **UAA does not start**. Given that an earlier attempt at
exactly this area already broke UAA boot once on this branch, gating construction on
`uaa.mtls-enabled` and degrading gracefully when the class is missing is cheap insurance.

### 4. Revocation behaviour is undocumented (`1cc3ed46e`)

`TlsClientAuthentication:412` sets `params.setRevocationEnabled(false)` — no CRL, no OCSP — and no
file under `docs/` mentions it. It is recorded in our review notes, but those are gitignored working
docs, not shipped documentation. Operators need this in `docs/`, since it defines what certificate
theft means for them.

### 5. Configuration parsing is duplicated three times (`09f1992dd`)

The same `additionalInformation` → `TlsClientAuthConfiguration` parsing exists in
`MtlsClaimsEnhancer:287`, `ClientDetailsAuthenticationProvider:321` and
`ClientAdminEndpointsValidator:623`. Three parsers for one format is how validation and enforcement
drift apart — the validator can accept a shape the enhancer reads differently. Not a live bug, but
his consolidation is the right shape.

### 6. Worth verifying rather than assumed (`a80e1c94f`)

He distinguishes "no certificate presented" from "required-claims not satisfied" *without exposing
claim values* in the error. Our messages should be checked for the same: the distinction is useful
for operators, and echoing a claim value back to an unauthenticated caller is an information leak.

## What our branch has and his does not

### 1. RFC 8705 §2.1.2 certificate subject binding — absent from his branch entirely

This is the headline, and it points the other way. A grep across his whole tree finds **no**
`tls_client_auth_subject_dn`, no `tls_client_auth_san_dns`, no `SUBJECT_BINDING_PARAMETERS`, and no
`TlsClientAuthSubjectMatcher`. His `TlsClientAuthConfiguration` declares only:

```text
tls-client-auth-ca
tls-client-auth-claim-mappings
tls-client-auth-sub-template
tls-client-auth-aud-templates
tls-client-auth-trusted-proxy-ca
tls-client-auth-required-claims
```

So on #3972 as it stands, **any certificate that chains to the configured CA authenticates as that
client.** `required-claims` is a partial mitigation, but it is optional, it is not the RFC mechanism,
and it gates on mapped claim *values* rather than on the certificate's registered subject.

That is exactly the population-trust hole we spent this review closing, in `7da4c6033` (red) /
`4c3e9706d` (green): exactly-one subject-binding parameter, exact matching, no wildcards, SAN type
checked, fail closed on zero or multiple.

It also has a forward consequence. The **CF Service Accounts proposal is built on
`tls_client_auth_san_dns`** — binding a managed client to `<name>.svc.identity`. Without our §2.1.2
work there is nothing for that design to bind to.

### 2. Identity-zone isolation

22 tests across both addressing modes (subdomain and `/z/{subdomain}`), including the same
`client_id` registered in two zones under different CAs, and the disabled-feature guard in a
non-default zone. His branch has no zone coverage; every mTLS test pins `IdentityZone.getUaa()`.

### 3. RFC 8705 §3.2 verification

End-to-end proof that `cnf` surfaces through `/introspect` and the legacy `/check_token`, for both
JWT and opaque token formats.

### 4. Red/green commit structure

The review asked for tests separated from production changes. He declines explicitly: "Tests and
production changes are committed together, so history is not a separate red/green sequence." Our
branch does split them (`7da4c6033` red → `4c3e9706d` green), which is what was asked for and is
materially easier to review.

## Addressed by neither branch

- Revocation actually **implemented** (CRL/OCSP) — documented-as-off at best.
- §2.2 `self_signed_tls_client_auth`, §3.4 client-declared metadata, §4 public-client cert binding.
- **Per-zone** mTLS enablement: `uaa.mtls-enabled` is global, so enabling it advertises
  `tls_client_auth` in every zone's discovery document and lets any zone admin register
  `tls-client-auth-ca`.
- Audit events for mTLS token issuance.
- A dedicated rate-limiter mapping for `/oauth/mtls/token` (CPU-bound; currently in the default
  global bucket).
- A test for **descendant** paths (`/oauth/mtls/token/...`). The security chain matcher and
  `isMtlsTokenPath` both cover the prefix, and he claims coverage for descendants; we have the
  behaviour but not the test.

## Suggested next steps

Port the four substantive items from his branch — they are independent of our subject-binding work
and do not conflict with it:

1. `ede683ee4` CA trust-bundle rotation (highest value; operational blocker without it)
2. `aa075f583` POST-only with `405` + `Allow: POST`
3. `cb5fbd889` skip mapper construction when disabled, tolerate the class being absent
4. `1cc3ed46e` document revocation behaviour in `docs/`

Then `09f1992dd`'s consolidation as a follow-up, and verify item 6 above.

The reverse direction matters more for the PR conversation: **§2.1.2 subject binding needs to land
on #3972**, or the merged feature keeps the "any cert from the CA is this client" behaviour, and the
Service Accounts proposal has no binding primitive to build on.
