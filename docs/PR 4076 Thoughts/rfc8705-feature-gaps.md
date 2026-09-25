# RFC 8705 features not implemented

UAA implements only the **PKI method** (§2.1, `tls_client_auth`). Everything below is either a
real gap in that method, or an entirely separate part of the spec that isn't wired up at all.

## Gaps in the method UAA does advertise (`tls_client_auth`)

| §   | Requirement | Status |
|-----|-------------|--------|
| 3.4 | Client registration metadata `tls_client_certificate_bound_access_tokens` — lets a *client* declare its own intent to receive bound tokens | **Not implemented.** UAA only implements the §3.3 *server*-side capability flag. There's no per-client field; every `tls_client_auth` token is unconditionally bound, which happens to satisfy the intent implicitly, but the client can't express it, and §3.4's explicit note about what to do when such a client connects over plain (non-mTLS) TLS has no corresponding logic. |
| 2.1 (§7.4) | Revocation checking — spec says it's a deployment decision, not a MUST, but explicitly names it as the mitigation for cert theft | **Not implemented.** `PKIXParameters.setRevocationEnabled(false)`, no CRL/OCSP anywhere. Flagged and deliberately accepted as informational in this session's security review (post-compromise only, and the intended credential — Diego instance-identity certs — is short-lived). |

**§3.2 correction:** an earlier version of this document listed §3.2 (`cnf` in token
introspection) as not implemented. That was wrong. `Claims`/`IntrospectionClaims` carry a
generic `@JsonAnySetter`/`@JsonAnyGetter` pair that round-trips any claim the JWT model doesn't
know about by name — including `cnf` — so it already flows through both `/introspect` and the
legacy `/check_token`, for both JWT- and opaque-format tokens (opaque tokens are looked up via
`RevocableTokenProvisioning` to the same underlying signed JWT that was built at issuance, so the
same claim survives). Verified end-to-end with real mTLS-issued tokens in
`MtlsTokenEndpointHardeningMockMvcTests` (group F, tests F1-F5): all five pass without any
production code change. §3.2 is fully implemented.

## Entire spec sections not wired up at all

| §   | Feature | Status |
|-----|---------|--------|
| 2.2 / 2.2.1 / 2.2.2 | **`self_signed_tls_client_auth` method** — client authenticates by presenting a certificate matching a `jwks`/`jwks_uri`-registered key, with *no* CA chain validation at all | **Not implemented.** Not in `ClientAuthentication`'s supported-methods list, not advertised in discovery, no code path reads `jwks`/`jwks_uri` for this purpose. A client without a CA-issued cert (e.g. a genuinely self-signed one, common for service-to-service outside CF) has no way to use mTLS auth here. |
| 4   | **Certificate-bound tokens for public clients** — bind an access token to whatever cert a client presented, without using the cert for *authentication* at all (no `client_id`/secret needed) | **Not implemented.** UAA's cert handling is entirely inside the `tls_client_auth` authentication path; there's no independent "bind token to TLS peer cert" mechanism usable by a public client. |
| 7.1 | Cert-bound **refresh tokens** | Effectively moot rather than missing: `ClientCredentialsTokenGranter` strips the refresh token for `tls_client_auth` + `client_credentials` entirely, so there's no refresh token to (mis)bind. If a future grant type combination did issue one, nothing checks the cert on redemption. |

## Correctly out of scope (not gaps)

- **§6.5 TLS termination** at a proxy — the spec explicitly punts this to the deployment; UAA's
  Gorouter/XFCC handling and the `tls-client-auth-trusted-proxy-ca` topology split already
  address the practical version of this.
- **§7.3 TLS version/cipher hygiene** — handled via the FIPS BCJSSE TLS 1.3 stack.
- **§5 `mtls_endpoint_aliases`**, **§3.1 `cnf.x5t#S256` on JWTs**, and **§3.2 `cnf` on token
  introspection** — all implemented (§3.2 confirmed by test, see correction above).

## Bottom line

For the one method UAA advertises, `tls_client_auth`, there is no remaining spec-level gap of
consequence: the two items left in the table above (§3.4 client-declared intent, §7.4 revocation)
are both explicitly optional in the RFC and were reviewed and consciously accepted. Everything
else missing is a separate authentication method (§2.2 self-signed) or a separate feature (§4
public-client cert binding) that this PR never set out to build. RFC conformance for
`tls_client_auth` itself is complete.
