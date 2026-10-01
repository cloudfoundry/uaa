# PR #4076 — description draft

Paste-ready text for the pull request. Keep it in step with `pr4076-develop-merge-evaluation.md`, which holds the
evidence behind every statement here.

---

## RFC 8705 mutual-TLS client authentication (`tls_client_auth`), hardened

Builds on #3972. Adds `tls_client_auth` client authentication at a dedicated `/oauth/mtls/token` endpoint, with
certificate-bound access tokens (`cnf.x5t#S256`), per-client trust configuration and optional RFC 8707 resource
indicators. **Off by default** (`uaa.mtls-enabled`, default `false`).

### What this adds beyond #3972

* **RFC 8705 section 2.1.2 subject binding.** A client with `tls-client-auth-ca` must also register exactly one expected
  subject value (`tls_client_auth_subject_dn` or one of the four `tls_client_auth_san_*` parameters). Chain validation
  alone only proves who issued a certificate; on a CA shared across tenants (Diego's instance-identity CA) it let any
  certificate holder authenticate as any client trusting that CA.
* The endpoint is `POST`-only, serves nothing below its path, issues only `client_credentials`, and is not an alias of
  `/oauth/token`.
* CA rotation bundles are fully trusted; expired certificates and CA certificates used as the leaf are refused.
* Claim mappings cannot target UAA-owned or authentication-context claims (`amr`, `acr`, `cnf`, ...), and a mapping's
  regex is bounded (256-character OU cap, 100 000-character match budget) so it cannot hang token issuance.
* Optional RFC 8707 `resource` parameter against a per-client allow-list (`tls-client-auth-allowed-resources`).
* Zone isolation in both zone-addressing modes.

### Behaviour with the flag off

The endpoint answers `404`, the Tomcat connector is untouched, no mTLS beans or filter chain are registered, the
registration APIs and `oauth.clients` bootstrap reject the keys, and discovery advertises nothing. The flag is read one
way everywhere (`true`, `1`, `yes`, `on`), so it cannot half-enable.

### Changes that reach deployments without the flag — please read

| Change | Who is affected |
|---|---|
| Discovery gains `tls_client_certificate_bound_access_tokens` (`false` when off; RFC 8705 section 3.3 treats omitted as `false`) | everyone, additive |
| An access token issued by a **refresh** no longer carries `granted_scopes`. It records the full consented scope set and belongs on the refresh token only; copying it onto a deliberately narrowed access token disclosed more than the caller was given. | deployments that register any `UaaTokenEnhancer` (stock UAA registers none unless this feature is on) |
| `UaaTokenEnhancer` gains a `default` method `getLateOverrideClaims()` (empty set). Other enhancers are not restricted or altered; `MtlsClaimsEnhancer` opts in for its own `sub`/`aud`. | source-compatible for all implementations |
| `ClientAdminEndpointsValidator`, `ClientAdminBootstrap`, `ClientDetailsAuthenticationProvider`, `ZoneEndpointsClientDetailsValidator` gained constructor parameters | only code that constructs them by hand |
| `UaaAuthenticationDetails` gains a field and has no `serialVersionUID`; session rows persisted by the previous version are expected to fail to deserialize after an upgrade | every deployment, at upgrade time — see below |
| A client whose `additionalInformation` already contains a key named `tls-client-auth-ca` is now treated as mTLS-only | none expected; nothing in UAA defined that key before |

`UaaAuthenticationDetails` is the one item here with no mitigation yet. It has been analysed but not exercised against a
live rolling upgrade; making the new field `transient`, or pinning `serialVersionUID`, removes the concern.

### Operational notes

* Enabling the flag is **connector-wide**: every TLS handshake to the instance now carries a `CertificateRequest` with no
  issuer constraint, and the connector moves to the FIPS BouncyCastle JSSE provider (required for TLS 1.3
  client-certificate requests). Soak-test interop and performance before enabling on a live foundation.
* UAA stamps `cnf` but does not enforce it; resource servers must compare the thumbprint with the certificate they see.
* Not implemented: revocation checking (PKIX runs with revocation off), per-zone enablement, audit events for mTLS token
  issuance, a dedicated rate-limit mapping for `/oauth/mtls/token`, `self_signed_tls_client_auth` and public-client
  certificate binding.

### Tests

New: roughly 330 test cases (222 in new files, the rest added to existing classes) across unit, Spring-context,
MockMvc (including the flag-off suite and a flag-consistency suite) and a real
embedded-Tomcat TLS integration test. No pre-existing test was deleted, renamed or disabled; the handful of changed
existing tests are listed with reasons in `pr4076-code-review-guide.md` section 2.

### Documentation

`docs/UAA-Client-Authentication.md` (configuration, certificate-bound tokens, error responses, compatibility notes),
`docs/UAA-Configuration-Reference.md` (`uaa.mtls-enabled`), the generated API docs (discovery, token endpoint,
introspection and check-token `cnf`, client registration keys) and the slate source.
