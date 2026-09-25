# Comparison: `review/pr3792-fix` vs. original PR [#3972](https://github.com/cloudfoundry/uaa/pull/3972)

Methodology: PR #3972's 100 commits are captured unchanged as this branch's first (squashed)
commit — verified byte-for-byte earlier in this session. So diffing that squashed commit against
current `HEAD` isolates exactly what the review/security work added, changed, or removed, with
zero noise from `develop` drift.

---

## 1. Preserved from PR #3972

The entire RFC 8705 feature surface is intact:

- **Dedicated endpoint** `/oauth/mtls/token`, advertised via OIDC discovery
  `mtls_endpoint_aliases.token_endpoint`.
- **Feature flag** `uaa.mtls-enabled` (default `false`), gating the connector-wide TLS
  reconfiguration and all client validation.
- **Per-client config options**, unchanged: `tls-client-auth-ca`, `tls-client-auth-trusted-proxy-ca`
  (Gorouter/XFCC topology selector), `tls-client-auth-claim-mappings` (cert subject field → JWT
  claim), `tls-client-auth-sub-template` / `tls-client-auth-aud-templates`,
  `tls-client-auth-required-claims`.
- **FIPS TLS 1.3 stack**: BCJSSE provider registration, `BCJSSESSLContext`,
  `MtlsClientAuthTomcatCustomizer`.
- **Certificate handling pipeline**: `RawPeerCertificateCaptureFilter` (captures the genuine
  handshake cert before the buildpack's `ClientCertificateMapper` overwrites the attribute with
  the XFCC-derived one), PKIX chain validation in `TlsClientAuthentication`, end-entity constraint
  checks, secretless client_credentials support (client API + zone API).
- **`MtlsClaimsEnhancer`**: cert → JWT claim mapping, dot-notation nesting, `cnf.x5t#S256`
  confirmation claim.
- **CF workflow**: app instance cert → `app_guid`/`space_guid`/`org_guid`/`cf_instance_guid`
  claims, verified end-to-end in the original PoC.

Nothing here was weakened or dropped — only tightened (see §3).

---

## 2. Removed from PR #3972

**One config-validation rule removed outright, as a bug fix, not a feature trade-off:**

`ClientAdminEndpointsValidator` used to reject *any* client whose `additionalInformation`
contained the key `token-endpoint-auth-method`, regardless of whether that client used mTLS:

```java
if (additionalInfo.containsKey(TOKEN_ENDPOINT_AUTH_METHOD)) {
    throw new InvalidClientDetailsException("token-endpoint-auth-method is not supported; ...");
}
```

This was part of PR #3972 itself. It broke create/update for *every* client carrying that
unrelated key (e.g. from a BOSH `oauth.clients` manifest) — collateral damage for a property mTLS
never used. Removed entirely.

**One redundant code path removed** (behavior-neutral): `ClientDetailsAuthenticationProvider` had
a second, dead-end branch that attempted `tls_client_auth` for a client with *no*
`tls-client-auth-ca` configured when it presented no credentials at `/oauth/mtls/token`. Since
such a client has no `TlsClientAuthConfiguration`, this branch always failed anyway
(`chain == null`) — removed in favor of an explicit up-front check, not a capability change.

**No config option was removed.** Everything else that shipped in #3972 is still accepted.

---

## 3. Security fixes made

### From Filip's own review of #3972 (pre-dating this session)

1. **mTLS-configured client can't fall back to `client_secret` at `/oauth/token`** — a client
   with `tls-client-auth-ca` is now exclusive to `/oauth/mtls/token`; previously it could obtain
   unbound tokens via its secret elsewhere, undermining the "tokens are always cert-bound"
   guarantee.
2. **`/oauth/mtls/token` no longer serves ordinary secret clients** — requires
   `tls-client-auth-ca` to even attempt the endpoint (`UaaTokenEndpoint` restriction).
3. **Grant-type restriction at the mTLS endpoint** —
   `UaaTokenEndpoint.rejectNonWorkloadGrantAtMtlsEndpoint`: only `client_credentials` may be
   issued there. Previously a `password` grant at that endpoint minted a token with `cnf`
   (cert-bound) *and* user identity claims simultaneously — two conflated identities in one token.
4. **Feature-disabled endpoint fails closed properly** — new `MtlsEndpointAvailabilityFilter`
   returns 404 when `uaa.mtls-enabled=false`, instead of silently falling through to the
   form-login/CSRF security chain.
5. **500→401 fix**: `InvalidClientDetailsException` from cert validation now converts to
   `BadCredentialsException`, closing an unauthenticated log-flooding vector on the Basic-auth
   path.
6. **Reserved/dotted claim bypass fixed twice** — `isReservedClaimName` catches `sub.foo`-style
   dotted mappings (previously bypassed the exact-match check on `sub`, `aud`, `cnf`, etc.),
   enforced both in `ClientAdminEndpointsValidator` (registration) and `MtlsClaimsEnhancer`
   (defense-in-depth for bootstrap-loaded clients).
7. **Constant-template subject forgery fixed** — `requireAtLeastOnePlaceholder`: a
   `tls-client-auth-sub-template` with no `{claim}` placeholder used to render to a fixed constant
   string, letting a client assert any `sub` value (including a real user's UUID), since
   `UaaTokenServices` re-applies `sub`/`aud` after its own defaults.

### From this session's security review

1. **`granted_scopes` leak into access tokens** — fixed by adding `GRANTED_SCOPES` to
   `NON_ADDITIONAL_ROOT_CLAIMS`. `MtlsClaimsEnhancer` had been registered as an unconditional
   `@Component`, which activated dormant code that copied the refresh token's full consented
   scope set onto every deliberately-narrowed access token, in *every* deployment — mTLS enabled
   or not.
2. **`MtlsClaimsEnhancer` gated on `uaa.mtls-enabled`** — makes the whole feature a true no-op
   when disabled, closing the blast radius of the previous fix and any future enhancer behavior.
3. **The headline fix — RFC 8705 §2.1.2 certificate subject binding**
    (`TlsClientAuthSubjectMatcher`, new). PR #3972 authenticated a client on **CA issuance
    alone**: any certificate the configured CA ever issued authenticated as *any* client trusting
    that CA. Since the flagship use case is the Diego instance-identity CA — shared by every app
    instance in a foundation — this meant **any co-tenant app could impersonate any other mTLS
    client in the same foundation**, demonstrated end-to-end in this session's
    `MtlsTokenEndpointHardeningMockMvcTests` (E1). Fixed by requiring exactly one of five new
    RFC-mandated subject parameters — `tls_client_auth_subject_dn`, `tls_client_auth_san_dns`,
    `tls_client_auth_san_uri`, `tls_client_auth_san_ip`, `tls_client_auth_san_email` — enforced at
    registration (all three creation paths: admin API, zone API, BOSH bootstrap) and again at
    authentication time.

    ⚠️ **Compatibility note, not a removal**: this makes a previously-optional nothing into a
    mandatory field. Any client configured under #3972's model with `tls-client-auth-ca` alone —
    no subject binding — is now rejected. That's the deliberate trade-off: the old "compliant"
    config was the vulnerable one.
4. **§3.3 discovery accuracy** — `tls_client_certificate_bound_access_tokens` now advertised
    (tied to `uaa.mtls-enabled`), since UAA does stamp `cnf.x5t#S256` and this metadata defaults
    to `false` when omitted.

**Net effect**: #3972's functionality and every one of its config options survive unchanged; one
buggy validation rule was deleted; and eleven security fixes were layered on top, the most
significant closing a cross-tenant impersonation path in the feature's own headline use case.
