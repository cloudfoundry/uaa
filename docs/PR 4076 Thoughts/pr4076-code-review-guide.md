# PR #4076 — code-review guide

Pull request: <https://github.com/cloudfoundry/uaa/pull/4076> ·
**base: `cloudfoundry/develop`** (diff taken from merge-base `6cc037111`, the tip of develop that the
branch forked from) · head: `review/pr3792-fix` ·
excluding documentation: 86 files changed, 12059 additions, 46 deletions.

## How to read this

- Every file and line reference is a link into the **PR's "Files changed" tab** (`#diff-<hash>` anchors,
  `R<n>` = line *n* on the new side). They open the file's diff and scroll to the range.
  GitHub collapses large diffs — if an anchor lands on a collapsed file, click *Load diff*.
- The links assume the PR head contains the latest push. Line anchors move if the branch is rebased or new commits are
  added.
- **Flag column** (`uaa.mtls-enabled`, default `false`):

| Mark | Meaning |
|---|---|
| ✅ **Gated** | does nothing observable when the flag is off |
| ⚪ **Inert** | not flag-gated, but cannot act unless something only the flag enables is present (e.g. path that 404s, a config key that can't be registered) |
| ⚠️ **Un-gated change** | behaviour changes without `uaa.mtls-enabled` being on — for every deployment, or (where stated) only for deployments that register a token enhancer. Review these hardest |
| 🔧 **Build/plumbing** | no runtime behaviour of its own |

Summary of the ⚠️ items (details in §1): **M1** `granted_scopes` is no longer copied from a refresh token onto the
refreshed access token — only for deployments that register a token enhancer (stock UAA with the flag off has none), but
then regardless of the flag ([UaaTokenServices](#uaatokenservices)); **M2** `UaaAuthenticationDetails` gains a field and
has no `serialVersionUID` ([UaaAuthenticationDetails](#uaaauthenticationdetails)); **widened `UAA_SUPPORTED_METHODS`**
([ClientAuthentication](#clientauthentication)) — contained by an external-IdP split;
`tls-client-auth-ca` is now an interpreted `additionalInformation` key
([ClientDetailsAuthenticationProvider](#clientdetailsauthenticationprovider)).
Fuller reasoning: `docs/PR 4076 Thoughts/pr4076-develop-merge-evaluation.md`.

---

## Section 1 — Changed production files

Grouped by module; within a module, ordered roughly by how much a reviewer should care.

### 1.1 Server — request path, security chain, token issuance

#### UaaTokenServices

`server/src/main/java/org/cloudfoundry/identity/uaa/oauth/UaaTokenServices.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-64c7c7e80abc3949a99f6a2b958afe7dbdc19686d8dbd249724f8be94e954228) | [NON_ADDITIONAL_ROOT_CLAIMS](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-64c7c7e80abc3949a99f6a2b958afe7dbdc19686d8dbd249724f8be94e954228R142-R149) | [lateOverrideClaims into createJWTAccessToken](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-64c7c7e80abc3949a99f6a2b958afe7dbdc19686d8dbd249724f8be94e954228R494-R495) | [late overrides applied](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-64c7c7e80abc3949a99f6a2b958afe7dbdc19686d8dbd249724f8be94e954228R604-R607) | [collect opt-ins from each enhancer](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-64c7c7e80abc3949a99f6a2b958afe7dbdc19686d8dbd249724f8be94e954228R680-R692) |
|---|---|---|---|---|

- **What changed:** (1) `GRANTED_SCOPES` added to `NON_ADDITIONAL_ROOT_CLAIMS`. (2) Enhancer output is applied to the
  access token **exactly as on develop** — before UAA's defaults, which take precedence for the claims UAA sets. (3)
  New: after its defaults, UAA applies the claims an enhancer both *named* in `getLateOverrideClaims()` and *returned*
  (`lateOverrideClaims`, threaded through `createCompositeToken` / `createJWTAccessToken`; the refresh path passes an
  empty map).
- **Why:** (1) A refresh must not copy the full consented-scope set onto a deliberately narrowed access token; the old
  `refreshTokenClaims.remove(GRANTED_SCOPES)` ran after the copy loop and never worked. (3) `MtlsClaimsEnhancer`'s
  certificate-identity `sub`/`aud` must survive UAA's defaults. It is an opt-in so that no *other* enhancer is
  restricted or changed: a third-party enhancer is responsible for its own output. (An earlier version of this PR
  instead filtered protected claim names out of every enhancer's output and let any enhancer's `sub`/`aud` win; that
  was reverted — see `pr4076-develop-merge-evaluation.md` M3.)
- **Flag:** (1) ⚠️ **Not gated by the flag, gated by the enhancer list (M1).** `getAdditionalRootClaims` copies
  refresh-token claims only when `uaaTokenEnhancers` is non-empty, so refreshed access tokens stop carrying
  `granted_scopes` for any deployment that registers a token enhancer — flag or no flag; stock UAA with the flag off
  has none and is unaffected. Kept by decision; belongs in the PR description. (2)/(3) ✅ no change for any enhancer
  that does not opt in, and nothing in the tree opts in except `MtlsClaimsEnhancer` (flag-gated).

#### UaaTokenEnhancer

`server/src/main/java/org/cloudfoundry/identity/uaa/oauth/UaaTokenEnhancer.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f94b6876ed5bf296dd7c4e0ab3b1ee72527fe7e408f08745d81017e2bc4a3e39) | [getLateOverrideClaims](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f94b6876ed5bf296dd7c4e0ab3b1ee72527fe7e408f08745d81017e2bc4a3e39R15-R27) |
|---|---|

- **What changed:** New `default Set<String> getLateOverrideClaims()` returning an empty set, with javadoc.
- **Why:** The explicit opt-in that lets one enhancer (the mTLS one) keep claims like `sub`/`aud` past UAA's defaults
  without changing what any other enhancer can do.
- **Flag:** ✅ **Source- and behaviour-compatible.** A `default` method: existing implementations (including
  closed-source ones) compile unchanged and get the empty set, i.e. exactly the previous behaviour. Only a *new*
  abstract method would have broken them.

#### ClientDetailsAuthenticationProvider

`server/src/main/java/org/cloudfoundry/identity/uaa/authentication/ClientDetailsAuthenticationProvider.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-97a689b081011268ba8460ed9e9345be7e77e224a7ee8a5d9392971110b4faa4) | [mTLS branch in additionalAuthenticationChecks](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-97a689b081011268ba8460ed9e9345be7e77e224a7ee8a5d9392971110b4faa4R90-R131) | [path check / validateTlsClientAuth / config parsing](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-97a689b081011268ba8460ed9e9345be7e77e224a7ee8a5d9392971110b4faa4R224-R371) |
|---|---|---|

- **What changed:** Adds a `TlsClientAuthentication` collaborator (constructor signature change). A client whose
  `additionalInformation` has `tls-client-auth-ca` is *exclusively* mTLS: it must authenticate at `/oauth/mtls/token`
  with no credentials, must register exactly one RFC 8705 §2.1.2 subject value, and is refused at `/oauth/token`.
  Conversely `/oauth/mtls/token` refuses any client without that config (so it is not an alias of `/oauth/token`).
  Validation = PKIX chain → `TlsClientAuthSubjectMatcher` → required-claims. A client with `tls-client-auth-ca` whose
  configuration cannot be read is refused rather than treated as ordinary. `InvalidClientDetailsException` is
  converted to `BadCredentialsException` (previously a 500 on the Basic-auth path). `isTlsClientAuthPath` answers true
  if *either* the decoded servlet path or the raw request path resolves to the endpoint (fail closed; handles
  `/oauth/%6dtls/token`).
- **Why:** RFC 8705 client authentication, and closing the cross-tenant impersonation hole where any cert chaining to
  a shared CA (Diego instance-identity) authenticated as any client trusting that CA.
- **Flag:** ⚪ **Inert when off, but not flag-gated in code.** Reachability is removed upstream: the endpoint 404s and
  `tls-client-auth-ca` cannot be registered. **Review point:** a *pre-existing* client that already happens to carry
  an `additionalInformation` key literally named `tls-client-auth-ca` would now be treated as mTLS-only and refused at
  `/oauth/token`. Nothing in UAA defined that key before this PR; check there are no foreign users. Also a
  state-transition case: clients registered with the flag on become inert (not insecure) after it is turned off — test
  E8.

#### UaaAuthenticationDetails

`server/src/main/java/org/cloudfoundry/identity/uaa/authentication/UaaAuthenticationDetails.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7f92051ccc7d95d8559a929bb820949ef8fe7902a6ee3803c55c7596cff03d12) | [new field](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7f92051ccc7d95d8559a929bb820949ef8fe7902a6ee3803c55c7596cff03d12R63-R72) | [populated from request](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7f92051ccc7d95d8559a929bb820949ef8fe7902a6ee3803c55c7596cff03d12R97) | [getter](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7f92051ccc7d95d8559a929bb820949ef8fe7902a6ee3803c55c7596cff03d12R175-R180) |
|---|---|---|---|

- **What changed:** New `@JsonIgnore private final String servletPath` (decoded servlet path) alongside `requestPath`,
  set in all three constructors, with a getter.
- **Why:** `requestPath` comes from `getRequestURI()` (raw, undecoded); the mTLS gate must see the same decoded path
  every other gate uses (`/oauth/%6dtls/token` bypass, security review §2).
- **Flag:** ⚠️ **Un-gated (M2).** The class `implements Serializable` and declares no `serialVersionUID`; adding a
  field changes the implicit one. It sits in the Spring-Session-JDBC-persisted security context, so session rows
  written by the previous version fail to deserialize after upgrade. Fix: make `servletPath` `transient` or pin the
  UID to develop's value.

#### UaaTokenEndpoint

`server/src/main/java/org/cloudfoundry/identity/uaa/oauth/token/UaaTokenEndpoint.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-47f9e5076c0950fa5b355dcd307f54f41c5d935336715a22a5c2033261161980) | [@RequestMapping adds /oauth/mtls/token](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-47f9e5076c0950fa5b355dcd307f54f41c5d935336715a22a5c2033261161980R81-R82) | [guards: grant type, RFC 8707 resource](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-47f9e5076c0950fa5b355dcd307f54f41c5d935336715a22a5c2033261161980R99-R235) |
|---|---|---|

- **What changed:** Type-level `@RequestMapping` now also maps `/oauth/mtls/token`. `doDelegateGet/Post` call two new
  guards that act only when the servlet path is the mTLS endpoint: `rejectNonWorkloadGrantAtMtlsEndpoint` (only
  `client_credentials`) and `enforceResourceIndicator` (RFC 8707 `resource`: ≤1 value, absolute URI without fragment,
  must be in the client's `tls-client-auth-allowed-resources`; else `invalid_target`).
- **Why:** Without the grant restriction a cert-authenticated client could trade a password for a user token stamped
  with `cnf`, asserting two identities in one token.
- **Flag:** ⚪ **Inert.** The mapping exists unconditionally but `MtlsEndpointAvailabilityFilter` 404s the path when
  the flag is off; both guards early-return on any other path. **Doc nit (L1):** the javadoc on
  `enforceResourceIndicator` still claims this is the only path into the granter so the enhancer needs no second check
  — disproved by security-review finding 1.

#### OauthEndpointSecurityConfiguration

`server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointSecurityConfiguration.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3da8b2670b01bbf1dba51a02397c9ae8101e1c80ee9dcacd753ee3abec13a199) | [mtlsTokenEndpointSecurity chain](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3da8b2670b01bbf1dba51a02397c9ae8101e1c80ee9dcacd753ee3abec13a199R469-R507) |
|---|---|

- **What changed:** New `mtlsTokenEndpointSecurity` `UaaFilterChain` at `FilterChainOrder.OAUTH_11`, matching
  `/oauth/mtls/token` and below: client-auth filters as in the token endpoint chain, stateless, CSRF off, anonymous
  off, `/**` requires full authentication.
- **Why:** Gives the endpoint its own OAuth chain instead of falling through to the catch-all browser (`uiSecurity`) chain.
- **Flag:** ✅ **Gated** by `@Conditional(MtlsEnabledCondition.class)` — bean absent when off.
  (`@ConditionalOnProperty` was replaced because it only accepts the literal `true`; see `MtlsEnabledCondition`.)

#### SpringServletXmlFiltersConfiguration

`server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlFiltersConfiguration.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-2871b6871f4cd69e143836e0d121725d079f52f745c7dca0397a9e5481d3d04e) | [three new FilterRegistrationBeans](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-2871b6871f4cd69e143836e0d121725d079f52f745c7dca0397a9e5481d3d04eR237-R311) |
|---|---|

- **What changed:** Registers `MtlsEndpointAvailabilityFilter` (order −290), `RawPeerCertificateCaptureFilter` (−300)
  and `clientCertificateMapperFilter` (−200, wraps the buildpack `ClientCertificateMapper` in `MtlsPathGuardedFilter`,
  reflectively because the class is package-private).
- **Why:** Order matters: capture the genuine TLS-peer cert *before* the mapper overwrites
  `jakarta.servlet.request.X509Certificate` with the XFCC-derived one; availability filter must run after zone-path
  rewriting and before Spring Security (−100).
- **Flag:** ✅ availability filter (flag arg) and ✅ mapper (registration `setEnabled(false)` and the buildpack class is
  never loaded when off). ⚪ capture filter is ungated — it only copies one attribute, and only on paths that 404 when
  off.

#### OauthEndpointBeanConfiguration

`server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-85f0aec01b02b5df2fe1c5a05d130ddb5a06e4f80280566dce56c63d272cdd61) | [clientAuthenticationProvider wiring](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-85f0aec01b02b5df2fe1c5a05d130ddb5a06e4f80280566dce56c63d272cdd61R464-R471) |
|---|---|

- **What changed:** Injects the `TlsClientAuthentication` component into `ClientDetailsAuthenticationProvider`.
- **Why:** Constructor change above.
- **Flag:** ⚪ `TlsClientAuthentication` is an ungated `@Component` but only used after the provider has seen a
  `tls-client-auth-ca` client on the mTLS path.

#### ClientCredentialsTokenGranter

`server/src/main/java/org/cloudfoundry/identity/uaa/oauth/provider/client/ClientCredentialsTokenGranter.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6281e42525a664a6e253e200903378c6d8803717214717921d66481069bb6eb9) | [ALLOWED_AUTH_METHODS](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6281e42525a664a6e253e200903378c6d8803717214717921d66481069bb6eb9R28-R32) |
|---|---|

- **What changed:** `tls_client_auth` added to the allowed client-auth methods for `client_credentials`; new static `isAllowedAuthMethod`.
- **Why:** Otherwise a cert-authenticated client could not obtain a client_credentials token.
- **Flag:** ⚪ Only reachable by a request whose `client_auth_method` is `tls_client_auth`, which only the mTLS path produces.

#### FilterChainOrder

`server/src/main/java/org/cloudfoundry/identity/uaa/web/FilterChainOrder.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5a0b2310d08e579bc68b9b8aa9c142e7a950f07f16f23819e91953b1569e42de) | [OAUTH_11](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5a0b2310d08e579bc68b9b8aa9c142e7a950f07f16f23819e91953b1569e42deR38) |
|---|---|

- **What changed:** Adds constant `OAUTH_11 = 211`.
- **Why:** Order slot for the new chain (after `OAUTH_10`, which has a disjoint matcher).
- **Flag:** 🔧 constant only.

### 1.2 Server — client registration and bootstrap

#### ClientAdminEndpointsValidator

`server/src/main/java/org/cloudfoundry/identity/uaa/client/ClientAdminEndpointsValidator.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-90bae85402d603904fc2b80c6bfdbc6a01a773f4bcd7a639a03cb45f3f558e0b) | [mtlsEnabled ctor param](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-90bae85402d603904fc2b80c6bfdbc6a01a773f4bcd7a639a03cb45f3f558e0bR94-R105) | [validate() hooks](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-90bae85402d603904fc2b80c6bfdbc6a01a773f4bcd7a639a03cb45f3f558e0bR139-R142) | [checkMtlsClientConfigAllowed + claim-config validation](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-90bae85402d603904fc2b80c6bfdbc6a01a773f4bcd7a639a03cb45f3f558e0bR372-R782) |
|---|---|---|---|

- **What changed:** Constructor takes `mtlsEnabled`. `validate` now calls `checkMtlsClientConfigAllowed` (rejects
  `tls-client-auth-ca`/`-trusted-proxy-ca` when off; parses PEMs; requires exactly one of the five §2.1.2 subject
  parameters) and `validateTlsClientAuthClaimConfig` (claim-mapping fields, reserved/dotted-reserved claim names,
  `pattern` only on `subject_ou` and with a capture group, template length ≤256 and ≥1 placeholder, placeholders must
  reference declared claims, required-claims shape, RFC 8707 allow-list shape, allow-list ⊕ aud-templates).
- **Why:** Registration-time enforcement so malformed or forgeable mTLS config never reaches token issuance.
- **Flag:** ✅ **Gated:** both calls are no-ops unless one of the `tls-client-auth-*` keys is present, and the CA keys
  throw when the flag is off. Existing clients without those keys are unaffected. Claim-mapping `pattern` complexity
  is bounded at *match* time in `TlsClientAuthentication` (see §3), not here.

#### ZoneEndpointsClientDetailsValidator

`server/src/main/java/org/cloudfoundry/identity/uaa/zone/ZoneEndpointsClientDetailsValidator.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e288f9a7cb11abcf41ed8c7ce49bb5abd232e439038bb80eea90a33d2ec3f640) | [ctor + flag](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e288f9a7cb11abcf41ed8c7ce49bb5abd232e439038bb80eea90a33d2ec3f640R34-R50) | [calls + secret relaxation](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e288f9a7cb11abcf41ed8c7ce49bb5abd232e439038bb80eea90a33d2ec3f640R61-R73) | [hasNonblankTlsClientAuthCa](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e288f9a7cb11abcf41ed8c7ce49bb5abd232e439038bb80eea90a33d2ec3f640R98-R109) |
|---|---|---|---|

- **What changed:** Takes `mtlsEnabled`; on CREATE runs the same two checks; a client with a non-blank CA string may
  omit `client_secret`; `getAdditionalInformation()` null-safe.
- **Why:** Zone-admin client API is a separate registration path that must obey the same flag.
- **Flag:** ✅ **Gated.** The secret relaxation can only trigger if `checkMtlsClientConfigAllowed` has already passed,
  i.e. flag on.

#### ClientAdminBootstrap

`server/src/main/java/org/cloudfoundry/identity/uaa/client/ClientAdminBootstrap.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-a5ed7d96d671169d8ed7630c7a0a65b58dcb08fb5aafd1383be4709dd902c3c5) | [ctor + flag](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-a5ed7d96d671169d8ed7630c7a0a65b58dcb08fb5aafd1383be4709dd902c3c5R84-R108) | [checks](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-a5ed7d96d671169d8ed7630c7a0a65b58dcb08fb5aafd1383be4709dd902c3c5R231-R233) |
|---|---|---|

- **What changed:** Takes `mtlsEnabled`; bootstrapped (BOSH `oauth.clients`) clients run the same two checks.
- **Why:** Bootstrap bypasses the admin API, so it needs its own enforcement.
- **Flag:** ✅ **Gated** (same no-op-without-keys behaviour).

#### SpringServletXmlBeansConfiguration

`server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-db52445807ff6a1a5700050e39ddf1245bcd848d7125354749a7753a11f6fc6e) | [clientDetailsValidator bean](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-db52445807ff6a1a5700050e39ddf1245bcd848d7125354749a7753a11f6fc6eR147-R149) |
|---|---|

- **What changed:** Passes `${uaa.mtls-enabled:false}` into `ClientAdminEndpointsValidator`.
- **Why:** Wiring.
- **Flag:** ✅ carries the flag.

### 1.3 Server — discovery and external IdPs

#### OpenIdConnectEndpoints

`server/src/main/java/org/cloudfoundry/identity/uaa/account/OpenIdConnectEndpoints.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-852d990f3ae2a9f9484fd9467d17cacadc1a493f4988a91984ae886fef23527c) | [flag + discovery](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-852d990f3ae2a9f9484fd9467d17cacadc1a493f4988a91984ae886fef23527cR19-R44) |
|---|---|

- **What changed:** Takes `mtlsEnabled`; builds the document with the 3-arg `OpenIdConfiguration`; when on, sets `mtls_endpoint_aliases.token_endpoint`.
- **Why:** RFC 8705 §5 / §3.3 metadata.
- **Flag:** ✅ **Gated.** Off → no `mtls_endpoint_aliases`, no `tls_client_auth` in
  `token_endpoint_auth_methods_supported`. One additive field is always emitted:
  `tls_client_certificate_bound_access_tokens` (`false` when off — the RFC default).

#### ExternalOAuthAuthenticationManager

`server/src/main/java/org/cloudfoundry/identity/uaa/provider/oauth/ExternalOAuthAuthenticationManager.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5de7e48a3ae0b4964650b7c580432d7993b5979a9b9291b35368afc2dad96ee3) | [code exchange](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5de7e48a3ae0b4964650b7c580432d7993b5979a9b9291b35368afc2dad96ee3R877-R880) | [oauthTokenRequest](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5de7e48a3ae0b4964650b7c580432d7993b5979a9b9291b35368afc2dad96ee3R1079-R1082) |
|---|---|---|

- **What changed:** Both outbound token-request sites throw `ProviderConfigurationException` if an IdP's `authMethod`
  is `tls_client_auth`.
- **Why:** UAA-as-relying-party has no client-cert plumbing; a stale/forced value must fail loudly before any request
  is sent.
- **Flag:** ⚠️→✅ ungated code, **behaviour-preserving**: external IdP accepts exactly the methods it accepted before.
  Tests pin the rejection of `tls_client_auth`.

#### ExternalOAuthIdentityProviderConfigValidator

`server/src/main/java/org/cloudfoundry/identity/uaa/provider/oauth/ExternalOAuthIdentityProviderConfigValidator.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-bc039ff328f3322e36b370d64e50d6f052c917ae93f873cc73f36fd923919e08) | [validator](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-bc039ff328f3322e36b370d64e50d6f052c917ae93f873cc73f36fd923919e08R70-R71) |
|---|---|

- **What changed:** Uses the new `isExternalOAuthMethodSupported` / `EXTERNAL_OAUTH_SUPPORTED_METHODS` (the old
  four-method list).
- **Why:** Widening `UAA_SUPPORTED_METHODS` must not leak `tls_client_auth` into relying-party config.
- **Flag:** ⚠️→✅ ungated code, **behaviour-preserving**: external IdP accepts exactly the methods it accepted before.
  Tests pin the rejection of `tls_client_auth`.

#### OauthIDPWrapperFactoryBean

`server/src/main/java/org/cloudfoundry/identity/uaa/provider/oauth/OauthIDPWrapperFactoryBean.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7fe935c99d89c5c6e2dfd598db1b93cb614fae0dc98600b599b13963404ecf0c) | [authMethod check](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7fe935c99d89c5c6e2dfd598db1b93cb614fae0dc98600b599b13963404ecf0cR194) |
|---|---|

- **What changed:** Same switch to `isExternalOAuthMethodSupported` for BOSH-supplied IdP definitions.
- **Why:** Same reason.
- **Flag:** ⚠️→✅ ungated code, **behaviour-preserving**: external IdP accepts exactly the methods it accepted before.
  Tests pin the rejection of `tls_client_auth`.

### 1.4 Model module

#### ClientAuthentication

`model/src/main/java/org/cloudfoundry/identity/uaa/constants/ClientAuthentication.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-34b82a78ec2cd71f602230156db21cd2bbb07e6b94846e794f1aefee5e53a4a6) | [constants + lists](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-34b82a78ec2cd71f602230156db21cd2bbb07e6b94846e794f1aefee5e53a4a6R22-R32) | [isValidMethod](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-34b82a78ec2cd71f602230156db21cd2bbb07e6b94846e794f1aefee5e53a4a6R42-R50) | [getCalculatedMethod](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-34b82a78ec2cd71f602230156db21cd2bbb07e6b94846e794f1aefee5e53a4a6R59-R78) |
|---|---|---|---|

- **What changed:** Adds `TLS_CLIENT_AUTH`; **adds it to `UAA_SUPPORTED_METHODS`**; new
  `EXTERNAL_OAUTH_SUPPORTED_METHODS` (old list) and `isExternalOAuthMethodSupported`; 4-arg
  `isValidMethod`/`getCalculatedMethod` with `hasCaConfig` (3-arg overloads delegate with `false`).
- **Why:** Registers the method and teaches the validity matrix that `tls_client_auth` needs a CA and forbids a secret/key.
- **Flag:** ⚠️ **Un-gated constant widening.** Every caller of `isMethodSupported`/`UAA_SUPPORTED_METHODS` now treats
  `tls_client_auth` as known. The audited external-IdP callers are split off (above); re-check for any other caller
  when reviewing.

#### OpenIdConfiguration

`model/src/main/java/org/cloudfoundry/identity/uaa/account/OpenIdConfiguration.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-03412341b99b75e7307ddce86c068d5d84ec3ff4fec0b1c0b1488073313ad7fe) | [tokenAMR default](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-03412341b99b75e7307ddce86c068d5d84ec3ff4fec0b1c0b1488073313ad7feR26) | [new fields + 2-arg ctor](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-03412341b99b75e7307ddce86c068d5d84ec3ff4fec0b1c0b1488073313ad7feR74-R101) | [3-arg ctor](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-03412341b99b75e7307ddce86c068d5d84ec3ff4fec0b1c0b1488073313ad7feR108-R113) |
|---|---|---|---|

- **What changed:** `tokenAMR` default gains `tls_client_auth`, **removed again in the constructor when `mtlsEnabled`
  is false**; new `mtls_endpoint_aliases` (`NON_NULL`) and `tls_client_certificate_bound_access_tokens`; new 3-arg
  constructor; the pre-existing 2-arg constructor now delegates with `false`.
- **Why:** Discovery metadata. The 2-arg default was `true` earlier on the branch (fail-open); fixed so the unchanged
  public signature produces the unchanged document.
- **Flag:** ✅ **Gated** by the constructor argument; default fails closed. Wire diff on a default deployment: one
  extra field, `tls_client_certificate_bound_access_tokens:false`. Note the *field initializer* default still contains
  `tls_client_auth` — only the constructors strip it; `@NoArgsConstructor` (Jackson) bypasses the strip.

#### UaaClientDetails

`model/src/main/java/org/cloudfoundry/identity/uaa/client/UaaClientDetails.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3b97388cdf7a96706747e8838d8603d622c6a56bb9dfb7e3290ceafe3c6581a4) | [field](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3b97388cdf7a96706747e8838d8603d622c6a56bb9dfb7e3290ceafe3c6581a4R90-R92) | [copy ctor](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3b97388cdf7a96706747e8838d8603d622c6a56bb9dfb7e3290ceafe3c6581a4R110-R112) | [setter / getter](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3b97388cdf7a96706747e8838d8603d622c6a56bb9dfb7e3290ceafe3c6581a4R312-R348) | [equals](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3b97388cdf7a96706747e8838d8603d622c6a56bb9dfb7e3290ceafe3c6581a4R391-R394) | [hashCode](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3b97388cdf7a96706747e8838d8603d622c6a56bb9dfb7e3290ceafe3c6581a4R428) |
|---|---|---|---|---|---|

- **What changed:** New `@JsonIgnore TlsClientAuthConfiguration` field; setter mirrors it into `additionalInformation`
  (and clears all keys on `null`); included in the copy constructor, `equals`, `hashCode`.
- **Why:** Typed access to the mTLS config.
- **Flag:** ⚪ **Inert** — **L3:** nothing in production calls the setter (JDBC clients carry the config in
  `additionalInformation`), so the “typed field first” fast paths in `MtlsClaimsEnhancer` and
  `UaaTokenEndpoint.allowedResourcesFor` are always a miss; the field is not `transient` while
  `TlsClientAuthConfiguration` is not `Serializable`; and it makes equal-config clients compare unequal depending on
  how they were built.

#### OAuth2Exception

`model/src/main/java/org/cloudfoundry/identity/uaa/oauth/common/exceptions/OAuth2Exception.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-fa723bdbd0cf1209636b796d51dc1765e2bf8fbd1cb1f4b26a9980359208ccff) | [constant](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-fa723bdbd0cf1209636b796d51dc1765e2bf8fbd1cb1f4b26a9980359208ccffR39) | [fromMap](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-fa723bdbd0cf1209636b796d51dc1765e2bf8fbd1cb1f4b26a9980359208ccffR118-R119) |
|---|---|---|

- **What changed:** Adds `INVALID_TARGET` and maps it to the new `InvalidTargetException`.
- **Why:** RFC 8707 error code.
- **Flag:** ⚪ additive constant/mapping; nothing emits it unless the mTLS path runs.

#### TokenConstants

`model/src/main/java/org/cloudfoundry/identity/uaa/oauth/token/TokenConstants.java`

| [whole file](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-58bee142a64a13d106819a64e7a84014b20f58919646201a67c3c627a495f7da) | [constant](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-58bee142a64a13d106819a64e7a84014b20f58919646201a67c3c627a495f7daR83) |
|---|---|

- **What changed:** `CLIENT_AUTH_TLS_CLIENT_AUTH`.
- **Why:** Name for the `client_auth_method` claim value.
- **Flag:** ⚪ additive constant/mapping; nothing emits it unless the mTLS path runs.

### 1.5 Build files

| File | Change | Flag |
|---|---|---|
| [libs.versions.toml](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-697f70cdd88ba88fe77eebda60c7e143f6ad1286bca75017421e93ad84fb87df) | adds `java-buildpack-client-certificate-mapper-jakarta` 2.0.1 and `spring-boot-tomcat` aliases | 🔧 (mapper jar is on the classpath for everyone but only *loaded* when the flag is on; `ClientCertificateMapperAutoConfigurationExclusionTest` guards against it self-registering) |
| [build.gradle.kts](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-47495b8210e183f2123b5dff215155b67df753098bad1d54c4770ed4003a488d) | `implementation` of both (the Tomcat customizer needs `spring-boot-tomcat`; the filter needs the mapper) | 🔧 (mapper jar is on the classpath for everyone but only *loaded* when the flag is on; `ClientCertificateMapperAutoConfigurationExclusionTest` guards against it self-registering) |
| [build.gradle.kts](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-9d2ae3b93599fbbac3205659f2b54d1be9042a19e42d577896330ee048817241) | `testImplementation(bouncyCastlePkixFips)` for cert generation in docs/MockMvc tests | 🔧 (mapper jar is on the classpath for everyone but only *loaded* when the flag is on; `ClientCertificateMapperAutoConfigurationExclusionTest` guards against it self-registering) |
| [index.html.md.erb](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-23e5e0a12a08795e817f8d11ed8dc3d77877a3938f49812f41c038efcd68c7d2) | API-docs source: the mTLS token-endpoint section (curl example, request parameters, response fields) and sub-sections on certificate-bound tokens (`cnf`, who enforces it), registering a client, and the endpoint's error responses | 🔧 (mapper jar is on the classpath for everyone but only *loaded* when the flag is on; `ClientCertificateMapperAutoConfigurationExclusionTest` guards against it self-registering) |

---

## Section 2 — Changed existing test files (the test itself changed)

Purely additive test methods are in §4a. This section is only for tests whose *existing* lines or configuration
changed. Across the PR, **no pre-existing `@Test`/`@ParameterizedTest`/`@Nested` was deleted, renamed or disabled**
(checked with the grep in `pr4076-backwards-compatibility-audit.md` §1).

### 2.1 Behavioural / expectation changes — read these

| Test | Change | Why | Impact |
|---|---|---|---|
| [UaaClientDetailsTest:279](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f5d2caecc7cd901e026b96552d8a2647314958da161f774d946e211fc347ec38R279) | `hashCode()).isPositive()` → `.isNotZero()` | `hashCode` now mixes in the new field and may be negative; `isPositive` asserted something `Object.hashCode` never promised | Weakens a smoke assertion only; equals/hashCode consistency is covered elsewhere. |
| [OpenIdConfiguration.json:77](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-63ae7065a17b5469be2e439cfa84c97af3cd1820ca082a416fcd33448e1d1080R77-R78) | adds `"tls_client_certificate_bound_access_tokens": false` | fixture is the serialized default discovery document | **The default discovery document grows by exactly one field** (additive; RFC 8705 §3.3 treats omitted as `false`). `tls_client_auth` is *not* in the fixture — default stays mTLS-free. |
| [TokenEndpointDocs:138](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-86a106e623eb6a382d51fa65a598a1ba2fead1e59baca2223dbdb8f6bf554e0eR138-R152) | `@TestPropertySource` gains `uaa.mtls-enabled=true` for the **whole class**; autowires `rawPeerCertificateCaptureFilterRegistration` (:217) | the new mTLS docs example cannot document a disabled endpoint | Enabling the flag registers `MtlsClaimsEnhancer`, which flips `UaaTokenServices` onto its enhancer code path for all 30 examples. The class javadoc records a measurement: 29 other examples' response key-sets and field tables are identical on/off. If the enhancer ever contributes claims for non-mTLS callers this guarantee breaks → move the example to its own class. |
| [OpenIdConnectEndpointDocs:47](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-57337b978d00ff9aa2b28e87e1dfb24e143d3d5ac122488b5d56fa257b0ff0dbR47-R50) | `ui_locales_supported` line gains a trailing comma; two `fieldWithPath` rows added (`mtls_endpoint_aliases.token_endpoint` optional/`STRING`, `tls_client_certificate_bound_access_tokens`) | published discovery example | Class stays on the default flag, so the published example shows what most deployments return; the alias is documented as conditional. The comma change is mechanical. |
| [OpenIdConnectEndpointsMockMvcTests:77](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-57ac7256bd3e8c33d7cf5729013a219394206924ab6ee4528d7e3564806704c6R77-R81) and […ZonePathTests:91](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f350860342fc1caaa886551bf2f38f5657459d41700aa68e4a85a22ccf2d2a28R91-R94) | extra assertion `getMtlsEndpointAliases()).isNull()` in the existing default-discovery test | earlier on the branch these classes were switched to `mtls-enabled=true`, which silently removed the default-deployment regression; they were reverted and *strengthened* | Pins that a default deployment (default zone and per-zone, both addressing modes) advertises no alias. Existing assertions untouched. |

### 2.2 Mechanical updates for changed production signatures (no assertion changed)

| Test | Edit | Because |
|---|---|---|
| [UaaClientAuthenticationProviderTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-cf0ac3dc1f3e6c462cec222074ba33abc94fb608d7f45c99edad11bf1b42393c) ([L50](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-cf0ac3dc1f3e6c462cec222074ba33abc94fb608d7f45c99edad11bf1b42393cR50), [L62](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-cf0ac3dc1f3e6c462cec222074ba33abc94fb608d7f45c99edad11bf1b42393cR62), [L68](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-cf0ac3dc1f3e6c462cec222074ba33abc94fb608d7f45c99edad11bf1b42393cR68)) | adds a `TlsClientAuthentication` mock and passes it to the new 4-arg `ClientDetailsAuthenticationProvider` constructor | `ClientDetailsAuthenticationProvider` ctor |
| [ClientAdminEndpointsTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-8a194de627a3fe8eb3ccaa4ecfcefadc8f922c6e1679c8936a2dce6245c72964) ([L124](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-8a194de627a3fe8eb3ccaa4ecfcefadc8f922c6e1679c8936a2dce6245c72964R124)) | `new ClientAdminEndpointsValidator(..., false)` | validator ctor gained `mtlsEnabled` |
| [ClientAdminEndpointsValidatorTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74) ([L107](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R107)) | same one-line ctor edit (the rest of the file is additive → §4a) | validator ctor |
| [ClientAdminBootstrapMultipleSecretsTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b7649eaa3a6e290cfcf0344fff1cae493265b2d41c67d00808a6192ca7f36eb6) ([L70](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b7649eaa3a6e290cfcf0344fff1cae493265b2d41c67d00808a6192ca7f36eb6R70)) | trailing `, false` argument | `ClientAdminBootstrap` ctor gained `mtlsEnabled` |
| [ClientAdminBootstrapMultipleSecretsUpdateTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-4505d429ac02238a7554caa830db666b3ae334306c0cfeea5019c8cc93bc6d76) ([L64](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-4505d429ac02238a7554caa830db666b3ae334306c0cfeea5019c8cc93bc6d76R64-R65)) | trailing `, false` argument | same |
| [ClientAdminBootstrapTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293a) ([L112](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR112), [L135](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR135-R136), [L156](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR156-R157), [L193](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR193), [L404](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR404), [L493](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR493)) | 5 ctor call sites get `false`; `@BeforeEach` registers `BouncyCastleFipsProvider` (the new tests parse real PEMs) | same; (rest additive → §4a) |
| [ClientAdminBootstrapProdEncoderTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b76c1782dd3a583a8c075a71b6f0a8ee24b4e324b4e44c97482ce838d2d62951) ([L88](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b76c1782dd3a583a8c075a71b6f0a8ee24b4e324b4e44c97482ce838d2d62951R88-R89)) | trailing `, false` argument (integration-test source set) | same |
| [ZoneEndpointsClientDetailsValidatorTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906) ([L72](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R72-R80)) | `@InjectMocks` removed in favour of explicit construction with the flag; BC FIPS provider registered | `ZoneEndpointsClientDetailsValidator` ctor gained `mtlsEnabled` (Mockito can't pick the primitive) |

### 2.3 Documentation classes: field descriptors added, no assertion changed

These are REST-docs classes (run by `docsTestRestDocs`, which feeds the slate API docs). Each only gains optional
field descriptors; the requests, responses and assertions are untouched, and the descriptors are optional so the
strict field checks still pass.

| Class | Added | Why |
|---|---|---|
| [ClientAdminEndpointDocs.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-25f42b3769ea26f93a2b705899875c0e7dc2d22fe7417bca66f36566cecfa136) ([L6](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-25f42b3769ea26f93a2b705899875c0e7dc2d22fe7417bca66f36566cecfa136R6), [L73-96](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-25f42b3769ea26f93a2b705899875c0e7dc2d22fe7417bca66f36566cecfa136R73-R96)) | the 14 `tls-client-auth-*` / `tls_client_auth_*` client keys, to `idempotentFields` (so create, update, get, list and tx all show them) | client registration is where an operator meets these keys; the private_key_jwt equivalent was already documented here |
| [IntrospectTokenEndpointDocs.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e3f36122b3f1ebdbcebddf09d84da29c296409984fa25deef494de00d4ae692b) ([L18](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e3f36122b3f1ebdbcebddf09d84da29c296409984fa25deef494de00d4ae692bR18), [L76-77](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e3f36122b3f1ebdbcebddf09d84da29c296409984fa25deef494de00d4ae692bR76-R77)) | optional `cnf` (RFC 8705 section 3.2) and `client_auth_method` response fields | introspection returns the confirmation claim for a bound token; a resource server needs to know |
| [CheckTokenEndpointDocs.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-fac299ae1784a2f336f0f8529571c34ad12ca0dad4c2b4cc29aefbc437e93120) ([L20](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-fac299ae1784a2f336f0f8529571c34ad12ca0dad4c2b4cc29aefbc437e93120R20), [L71-72](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-fac299ae1784a2f336f0f8529571c34ad12ca0dad4c2b4cc29aefbc437e93120R71-R72)) | the same two optional response fields | `/check_token` returns them too |

Source-compat note: these ctor changes remove the old public signatures (no deprecated overloads). Internal
Spring-wired classes, but anyone constructing them by hand must add the argument.

---

## Section 3 — New production files

All new, so the diff is the whole file. Flag column as in the legend.

| Module | File | Summary | Flag |
|---|---|---|---|
| server | [TlsClientAuthentication.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5b2a9141bd4167c7b204f9adf5d14c31de185da11b6ac91e11af28bc78fe56be) | `@Component`. PKIX validation of a client chain against the per-client CA (all PEMs in a bundle are anchors → CA rotation), end-entity constraints (not a CA, KeyUsage digitalSignature, EKU clientAuth/any), trusted-proxy validation for XFCC, claim-mapping extraction (CN/OU/O, escaped commas, multi-valued RDNs) with the regex work bounded — an OU over 256 characters is not matched, a match reading more than 100 000 characters is abandoned (that mapping then yields no claim), and each pattern is compiled once in a bounded cache — required-claims check, and selection of the right chain per trust model (direct vs proxy-only). Revocation is off (`setRevocationEnabled(false)`). | ⚪ |
| server | [TlsClientAuthSubjectMatcher.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-373a0e3501b26d21a2828c853d05e46f8ae21d40209931a1240d83f95ef763c1) | RFC 8705 §2.1.2 exact binding: `tls_client_auth_subject_dn` (LdapName compare, order-significant), `…_san_dns/uri/ip/email` (typed SAN match; IP compared in binary form). Fails closed unless exactly one binding is configured. This is the headline security fix over #3972. | ⚪ |
| server | [MtlsClaimsEnhancer.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f41c46fe99944974a318a87fb57fd471f2f74b7112b96b55a67543609b2bfb80) | `UaaTokenEnhancer`. For `tls_client_auth` requests only: certificate-derived claims (dot-notation nesting, reserved names skipped), `cnf.x5t#S256`, `sub`/`aud` templates, and the RFC 8707 `resource` → `aud` (re-checked against the allow-list even though the endpoint already did). Fails closed — the token request fails — if `cnf` cannot be computed, if the client's configuration cannot be resolved, or if no certificate can be resolved, for a request that authenticated with one. Overrides `getLateOverrideClaims()` to return `{sub, aud}` — its only opt-in past UAA's defaults. **L2:** unguarded `(UaaClientDetails)` cast and a comment referring to handling that isn't there. | ✅ `@Conditional(MtlsEnabledCondition)` (via the bean definition) |
| server | [MtlsEnabledCondition.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7ac690bd7c194500041de0857725634bd1a6eb85c9cbf25322ee9d1ee906cbcc) | Spring `Condition` reading `uaa.mtls-enabled` via `Environment.getProperty(.., Boolean.class, false)` so `1/yes/on` mean the same as for `@Value boolean` injection — prevents a half-enabled feature. | ✅ is the gate |
| server | [MtlsEndpointAvailabilityFilter.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-ea1929ca11d1a80e9a840c0c3814f6f88412f774a247022c19c5eda0004c8f37) | Order −290. Off → 404; any path below `/oauth/mtls/token` → 404 (closes the `/oauth/mtls/token/oauth/token` routing bypass); non-POST → 405 + `Allow: POST`. Only ever denies. | ✅ |
| server | [RawPeerCertificateCaptureFilter.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-db53724b287c0f558de0f4ccfa2604d3762e817ee52a7b630cba3b3c33169ac0) | Order −300. Copies the genuine handshake peer cert into a private attribute before the mapper overwrites the standard one; exposes `isMtlsTokenPath` used across the feature (prefix semantics). | ⚪ ungated, harmless |
| server | [MtlsPathGuardedFilter.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-df34d51940d46426dffd0a81d83fb1be8fe66ff4e6dee987c14d0748e03ebf23) | Wraps the buildpack `ClientCertificateMapper` so it only runs on the effective (post zone-rewrite) mTLS path. | ✅ only constructed when on |
| server | [MtlsClientAuthTomcatCustomizer.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7b90ee40aace29285a9829e14e6e41cb891a52f31cfcbaa245e18f38b044d072) | `WebServerFactoryCustomizer`: when on, installs `BCJSSESslImplementation`, sets `certificateVerification=optionalNoCA` and `NoAcceptedIssuersTrustManager` on every `SSLHostConfig`; idempotently registers BCFIPS + BCJSSE and fails fast if impostor/non-FIPS providers hold those names. **Connector-wide**, not per-endpoint — every TLS handshake now gets a CertificateRequest with no issuer list. | ✅ returns before touching the connector when off |
| server | [BCJSSEUtil.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-d2ebe68d3fba1cb65ac805cc87d0a1b17d6680d083538272aba1661e9ac6487a) | Tomcat `JSSEUtil` backed by BCJSSE; advertises TLS 1.3 renegotiable auth; sources implemented protocols/ciphers from BCJSSE (SunJSSE's set includes `SSLv2Hello`, which BCJSSE rejects). | ✅ (only reachable via the customizer) |
| server | [BCJSSESSLContext.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-4c80fc0ddf99554eba972b7da301e665b97a959f142befb14c5f973cf66c2310) | Tomcat `SSLContext` adapter over `javax.net.ssl.SSLContext` from the BCJSSE provider. | ✅ |
| server | [BCJSSESslImplementation.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6d9d5d067533aa64579a858a1970164ba211eb444743790b63bf6bcf0baaa017) | `JSSEImplementation` returning `BCJSSEUtil`; named via `sslImplementationName` so only this connector uses BCJSSE. | ✅ |
| server | [NoAcceptedIssuersTrustManager.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-3ff0a65eab1ab1cb26ffbba1e2a2d7dbb8553c96aaec861e18fadbea12a42228) | `X509TrustManager` with no-op checks and an empty accepted-issuers list, so Go-based clients (Gorouter) aren't told “only public CAs” and don't send an empty Certificate. | ✅ |
| model | [TlsClientAuthConfiguration.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5f34c0b323f4bc06fd6bedf4ad5d6a4a5d1e7281a9b6c9b93874694f5f3eae37) | Model for all `tls-client-auth-*` keys (CA, trusted-proxy CA, claim mappings, sub/aud templates, required claims, allowed resources, five §2.1.2 subject parameters), the reserved-claim set (`isReservedClaimName` also catches dotted children), `isConfigured`, `configuredSubjectBindings`. | ⚪ data class |
| model | [InvalidTargetException.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-64be387db6d1e9e080120790136293dbae26b45f584ef411ead3e449b662ca2e) | RFC 8707 `invalid_target`, HTTP 400. | ⚪ |

---

## Section 4 — New tests

### 4a. Tests added to existing test classes

**[OpenIdConfigurationTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b93a41add46c20e89f0db7073e1b557b6900de46c72fa8b4d991740ee7b2e51f)**

Discovery model: default advertises nothing; flag-on advertises `tls_client_auth`; the 2-arg ctor fails closed.

Tests:

- [`mtlsEndpointAliasesIsNullByDefault`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b93a41add46c20e89f0db7073e1b557b6900de46c72fa8b4d991740ee7b2e51fR71)
- [`mtlsEndpointAliasesCanBeSet`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b93a41add46c20e89f0db7073e1b557b6900de46c72fa8b4d991740ee7b2e51fR77)
- [`theConstructorWithoutAnMtlsFlagAdvertisesNoMtlsSupport`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b93a41add46c20e89f0db7073e1b557b6900de46c72fa8b4d991740ee7b2e51fR91)
- [`tlsClientAuthIsExcludedWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b93a41add46c20e89f0db7073e1b557b6900de46c72fa8b4d991740ee7b2e51fR105)
- [`tlsClientAuthIsIncludedWhenMtlsEnabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b93a41add46c20e89f0db7073e1b557b6900de46c72fa8b4d991740ee7b2e51fR113)

**[UaaClientDetailsTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f5d2caecc7cd901e026b96552d8a2647314958da161f774d946e211fc347ec38)**

Copy-constructor keeps flat `tls-client-auth-*` info when typed config is null; JSON round trip; clearing removes all
six keys.

Tests:

- [`copiesFlatTlsClientAuthAdditionalInformationWhenTypedConfigurationIsNull`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f5d2caecc7cd901e026b96552d8a2647314958da161f774d946e211fc347ec38R63)
- [`tlsClientAuthConfigRoundTripsViaJson`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f5d2caecc7cd901e026b96552d8a2647314958da161f774d946e211fc347ec38R228)
- [`setTlsClientAuthConfiguration_whenCleared_removesAllPersistedSettings`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f5d2caecc7cd901e026b96552d8a2647314958da161f774d946e211fc347ec38R245)

**[ClientAuthenticationTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198a)**

The `isValidMethod`/`getCalculatedMethod` matrix with `hasCaConfig`; external-IdP list excludes `tls_client_auth`.

Tests:

- [`externalOAuthMethodsSupportStandardMethodsButNotTlsClientAuth`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR29)
- [`tlsClientAuthIsARecognisedMethod`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR93)
- [`tlsClientAuthDoesNotRequireASecret`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR98)
- [`tlsClientAuthIsCalculatedWhenHasCaConfig`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR103)
- [`tlsClientAuthIsValidMethodWhenHasCaConfig`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR109)
- [`tlsClientAuthIsInvalidWithoutCaConfig`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR115)
- [`tlsClientAuthIsInvalidWhenHasSecret`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR121)
- [`tlsClientAuthIsInvalidWhenHasKeyConfig`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR127)
- [`tlsClientAuthIsValidMethodWhenHasCaConfigAndMethodUnset`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR133)
- [`tlsClientAuthIsInvalidWhenMethodUnsetAndHasSecretAndCaConfig`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR140)
- [`tlsClientAuthIsInvalidWhenMethodUnsetAndHasKeyConfigAndCaConfig`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e74abf42c61421897d4afb164be2db2d88e888f3bde952f6fd31875a2935198aR145)

**[UaaClientAuthenticationProviderTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-cf0ac3dc1f3e6c462cec222074ba33abc94fb608d7f45c99edad11bf1b42393c)**

A secret presented for a `tls-client-auth-ca` client is refused (`BadCredentialsException`).

Tests:

- [`provider_rejectsClientSecretForClientConfiguredForTlsClientAuth`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-cf0ac3dc1f3e6c462cec222074ba33abc94fb608d7f45c99edad11bf1b42393cR130)

**[ClientAdminBootstrapTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293a)**

BOSH-bootstrap path honours the flag and the §2.1.2 / claim-config rules (flag off rejects; on accepts; zero/two/blank
subject bindings rejected; SAN binding OK; ordinary client unaffected when off).

Tests:

- [`mtlsClientConfigRejectedWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR679)
- [`mtlsClientTrustedProxyConfigRejectedWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR690)
- [`mtlsClientConfigAllowedWhenMtlsEnabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR701)
- [`nestedTlsClientAuthConfigurationIsRejectedDuringBootstrap`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR726)
- [`invalidTlsClientAuthClaimConfigIsRejectedDuringBootstrap`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR751)
- [`mtlsClientWithNoSubjectBindingIsRejectedDuringBootstrap`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR798)
- [`mtlsClientWithTwoSubjectBindingsIsRejectedDuringBootstrap`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR809)
- [`mtlsClientWithBlankSubjectBindingIsRejectedDuringBootstrap`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR822)
- [`mtlsClientWithASanBindingBootstrapsSuccessfully`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR836)
- [`mtlsClientWithRequiredClaimsButNoSubjectBindingIsRejectedDuringBootstrap`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR850)
- [`ordinaryClientBootstrapsSuccessfullyWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-c6602a1f1670a61412d43894163f97e0b475941c0a19d1209edaaf7decb9293aR866)

**[ClientAdminEndpointsValidatorTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74)**

Largest block (~560 lines): flag gating, the five-parameter §2.1.2 rule (parameterised), PEM validation, and ~30
`validateTlsClientAuthClaimConfig_*` cases (patterns only on `subject_ou` with a capture group, reserved and
dotted-reserved claims, templates, required-claims, length bounds). Several are labelled `COPILOT REVIEW` from the
upstream review round.

Added at:

- [L347-910](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R347-R910)

Tests:

- [`rejectsTlsClientAuthCaWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R349)
- [`rejectsTlsClientAuthTrustedProxyCaWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R364)
- [`allowsTlsClientAuthCaWithExactlyOneSubjectBinding`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R401)
- [`acceptsEachOfTheFiveSubjectParameters`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R419)
- [`rejectsTlsClientAuthCaWithNoSubjectBinding`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R427)
- [`rejectsTlsClientAuthCaWithMoreThanOneSubjectBinding`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R439)
- [`rejectsBlankSubjectBindingValue`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R450)
- [`requiredClaimsAloneDoesNotSatisfySubjectBinding`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R461)
- [`allowsRequiredClaimsAlongsideASubjectBinding`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R474)
- [`rejectsNestedTlsClientAuthConfigurationWhenMtlsEnabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R497)
- [`rejectsBlankTlsClientAuthTrustedProxyCaWhenMtlsEnabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R512)
- [`rejectsMalformedTlsClientAuthTrustedProxyCaWhenMtlsEnabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R528)
- [`rejectsMalformedTlsClientAuthCaWhenMtlsEnabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R543)
- [`allowsClientWithoutMtlsFieldsWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R558)
- [`validateTlsClientAuthClaimConfig_rejectsReservedClaim`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R682)
- [`validateTlsClientAuthClaimConfig_rejectsDottedClaimWhoseParentIsReserved`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R694)
- [`validateTlsClientAuthClaimConfig_rejectsPatternOnSubjectCn`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R606)
- [`validateTlsClientAuthClaimConfig_rejectsCaptureGrouplessOuPattern`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R635)
- [`validateTlsClientAuthClaimConfig_rejectsSubTemplateExceedingMaxLength`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R853)
- [`validateTlsClientAuthClaimConfig_rejectsPlaceholderlessSubTemplateAtMaxLengthQuickly`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R887)
- [`validateTlsClientAuthClaimConfig_acceptsFullyValidConfig`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-66c997ca028c7129ab8dd5dd88e399da34047f82dc581fc3f03ed9f2329ffa74R835)

**[ZoneEndpointsClientDetailsValidatorTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906)**

Zone-client API: flag gating, secretless clients allowed only with a valid non-blank CA string (JSON-map, non-string,
blank and unsupported values rejected), supplied secrets still policy-checked.

Tests:

- [`rejectsSecretlessClientCredentialsClientWhenAdditionalInformationIsNull`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R126)
- [`rejectsTlsClientAuthCaWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R167)
- [`allowsTlsClientAuthCaWhenMtlsEnabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R183)
- [`allowsSecretlessClientCredentialsClientWhenTlsClientAuthCaConfigured`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R201)
- [`rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaIsJsonMap`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R215)
- [`rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaMapHasUnsupportedCaValue`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R232)
- [`rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaMapIsMalformed`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R249)
- [`rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaIsBlank`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R265)
- [`rejectsSecretlessClientCredentialsClientWhenTlsClientAuthCaIsNotAString`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R280)
- [`stillValidatesSuppliedSecretWhenTlsClientAuthCaConfigured`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R295)
- [`allowsClientWithoutMtlsFieldsWhenMtlsDisabled`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-6e25927aca2a878c84efa4e72ef8c8f4ea7efc8997dbbafaaf5a9a1d2ded3906R312)

**[ClientCredentialsTokenGranterTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-8392d93de9b5c57128e4649cf10b123bfadd54d3837d3e907797a45174cf54f4)**

`tls_client_auth` is allowed for client_credentials.

Tests:

- [`tlsClientAuthIsAllowedForClientCredentials`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-8392d93de9b5c57128e4649cf10b123bfadd54d3837d3e907797a45174cf54f4R71)

**[UaaTokenEndpointTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-a19ab68544bddcf5a77cd6e066f1dd5a82a67370e075b2502608a1a554a9d253)**

Reflection test that the controller maps `/oauth/mtls/token` and its descendants (the premise of the routing-bypass fix).

Tests:

- [`mapsMtlsTokenEndpointAndItsDescendants`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-a19ab68544bddcf5a77cd6e066f1dd5a82a67370e075b2502608a1a554a9d253R76)

**[ExternalOAuthAuthenticationManagerTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-eba44d881ee6a9b4473950fbb02320937edb98d551af0a658f61ec359ce0e8c6)**

A stale `tls_client_auth` on an external IdP fails before any request is sent (both code-exchange and token-request paths).

Tests:

- [`oauthTokenRequestRejectsStaleTlsClientAuthMethodBeforeSendingRequest`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-eba44d881ee6a9b4473950fbb02320937edb98d551af0a658f61ec359ce0e8c6R862)
- [`authorizationCodeExchangeRejectsStaleTlsClientAuthMethodBeforeSendingRequest`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-eba44d881ee6a9b4473950fbb02320937edb98d551af0a658f61ec359ce0e8c6R877)

**[ExternalOAuthIdentityProviderConfigValidatorTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e1e9d44a3de5f2ae4fbb5421a34a14715c995bc6585bdb3b6a602b70da1b0733)**

Validator rejects `tls_client_auth` on an external IdP.

Tests:

- [`configWithTlsClientAuthMethod_ThrowsException`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-e1e9d44a3de5f2ae4fbb5421a34a14715c995bc6585bdb3b6a602b70da1b0733R115)

**[OauthIdentityProviderDefinitionFactoryBeanTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f941999144a906931d44045832be571ee2874de80265a762d87fd0fc6d87d01d)**

BOSH IdP factory rejects `tls_client_auth`.

Tests:

- [`authMethodSetToTlsClientAuthIsRejected`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f941999144a906931d44045832be571ee2874de80265a762d87fd0fc6d87d01dR332)

**[TokenEndpointDocs.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-86a106e623eb6a382d51fa65a598a1ba2fead1e59baca2223dbdb8f6bf554e0e)**

REST-docs example for the mTLS client-credentials grant (generates a CA + leaf in-test).

Tests:

- [`getTokenUsingClientCredentialGrantWithTlsClientAuth`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-86a106e623eb6a382d51fa65a598a1ba2fead1e59baca2223dbdb8f6bf554e0eR542)

**[UaaTokenServicesTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299e)**

Three groups: **M1** — refresh with a narrowed scope must not leak `granted_scopes`; the enhancer contract — an
opted-in enhancer's `sub`/`aud` win, protected claims cannot be overridden, custom claims still apply; and
**coexistence** (`WhenMtlsClaimsEnhancerSharesTheEnhancerList`) — the real `MtlsClaimsEnhancer` is inert for non-mTLS
requests and opts in to `sub`/`aud` only, claims from several enhancers coexist in either order, the later enhancer
wins a collision, and **another enhancer is unrestricted**: claims UAA does not set for the grant survive, and its
`sub`/`aud` do not displace UAA's, exactly as on develop. These two were committed red (`448d872a9`) and fail on the
branch without `3383975fe`.

Tests:

- [`refreshWithNarrowedScopeMustNotLeakGrantedScopesIntoTheAccessToken`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR503)
- [`enhancerSubAndAudClaimsWinOverUaaDefaults`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1009)
- [`enhancerCannotOverrideProtectedClaims`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1064)
- [`enhancerCanStillAddCustomClaims`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1123)
- [`mtlsEnhancerIsInertForARequestThatIsNotTlsClientAuth`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1204)
- [`claimsFromBothEnhancersCoexistInEitherOrder`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1221)
- [`laterEnhancerWinsACustomClaimCollision`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1238)
- [`claimsUaaDoesNotSetForTheGrantSurviveFromAnotherEnhancer`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1248)
- [`subAndAudFromAnotherEnhancerDoNotWin`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1266)
- [`mtlsEnhancerOptsInToSubAndAudOnly`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1279)
- [`anEnhancerDoesNotOptInByDefault`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1287)
- [`optInAppliesOnlyTheNamedClaimsThatWereReturned`](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1c3e223365efca985eb7ad3224f4535e10159f6a17d3ac0cff368a2bbaaf299eR1293)

### 4b. New test files

Counts are `@Test`/`@ParameterizedTest` annotations in the file. Ordered unit → Spring-context → MockMvc/integration.

| File | Tests | What it proves |
|---|---|---|
| [TlsClientAuthConfigurationTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f5140f4cce21fabf713a1d99da25ef83afc50509a3a1e639e214b65db9076e9d) | 18 | Model: reserved/dotted-reserved claim names, JSON round trips of every key, `isConfigured`, equality. |
| [TlsClientAuthSubjectMatcherTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-25ed48005ce98feecbb07d61009b6bd1e0e3ce4fc492a38f6a46a912ce0d83a9) | 17 | §2.1.2 matching: DN (case/spacing-insensitive, order-sensitive, unparseable → no match), each SAN type, cross-type SAN confusion rejected, IP in binary form, exactly-one-binding rule. |
| [TlsClientAuthenticationTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-b96b9f1410248c513b73455800a9ffeeecd6b9a37faf04be741a50bea0f654df) | 45 | PKIX validation (expired, intermediates, trust anchor in/out of chain, CA-as-leaf, EKU/KeyUsage), trusted-proxy checks, claim extraction incl. multi-valued RDNs, regex step budget / OU length cap / pattern cache, required-claims, chain selection for direct vs XFCC, mapper-silently-failed guard. |
| [MtlsClaimsEnhancerTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-a551b15dc02a149657bc5a4d6dbbd206e96d260a19402101c19e8f4fad1505ce) | 29 | Claim mapping, nesting, reserved names, sub/aud templates, `cnf` thumbprint, only-for-`tls_client_auth`, fail-closed on lookup/encoding failure and on an unresolvable configuration or certificate, RFC 8707 allow-list re-check. |
| [MtlsEnabledConditionTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5857fe058a9b71bab86d4bb9b992500b8f77dc5cb1efbf11757e838571016f36) | 3 | All truthy spellings match; falsy and absent don't — pins the one-meaning flag. |
| [RawPeerCertificateCaptureFilterTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-cb8200e4cc7ea51dcf84b0cfaa8559adacac9278673ad73a8b1b6c1e55fe5c02) | 2 | Peer cert copied to the private attribute (or null). |
| [RawPeerCertificateCaptureFilterRegistrationTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1265a19523b801f5d00c4d1e7beced533c455f2d940c2ba1bc76a16b6d13fdf7) | 6 | Filter ordering vs the mapper; effective-path matching incl. zone-path; captured attribute survives the mapper overwriting the standard one. |
| [ClientCertificateMapperFilterTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-a0d9cbe9ad5710f531ac752d4d18774aa8506bbce482ddd193343dde85b2d6a5) | 5 | Mapper registered only for the mTLS path, not constructed when off, populates the cert attribute before Security runs. |
| [ClientCertificateMapperAutoConfigurationExclusionTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-29136198aee8539b2f6faaf3e05e9388a9cf4f946ac17204ae9b40d2637cb8be) | 2 | Fails the build if the mapper jar ever ships an auto-config or `ServletContainerInitializer` registration. |
| [OauthEndpointSecurityConfigurationTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-7a5387be5d51a0dc2967a989f13f9e25d2c997098d239aef3f87a4e9c1767b9c) | 1 | The mTLS security chain exists only when the flag is on. |
| [ClientDetailsAuthenticationProviderTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-cf3f0276317e6e4ec956620aeffb95fc6ea74d04bf2d798c1a4b2c3ec9957261) | 14 | mTLS path detection (decoded servlet path vs raw URI, descendants), config parsing from flat `additionalInformation`, required-claims enforced against a client sharing the same CA, and a client whose configuration cannot be read is refused. |
| [OpenIdConnectEndpointsTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-09f45b39c1175cd0d907d9c53602186ef395b775f51820136c213d8ca52781f6) | 4 | Discovery alias and the three advertisements move together, on and off. |
| [MtlsClientAuthTomcatCustomizerTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-1d8bff9aabf2268fa74d901c7bcc7b275783c0b65f03cc6f1b296605fa12dbdc) | 11 | Connector settings, no-op when off, BCFIPS/BCJSSE registration idempotence and impostor/non-FIPS fail-fast. |
| [BCJSSEUtilTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-bb34891b49b3f952376413259a5fce0839a8e7782e55a83ba3cf6d3f691a06ed) | 1 | Enabled protocols exclude `SSLv2Hello`, include TLS 1.3. |
| [BCJSSESSLContextTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-a44445fdaf5b5616901c9b1878e7c0a7bf759306b26aadf1ab3b4377a14e76f4) | 2 | TLS 1.2/1.3 from BCJSSE; clear error when provider missing. |
| [MtlsClientAuthTomcatCustomizerIntegrationTest.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-ee382ba0e14bea9129814a36bf87b80dff532271d911cf0d2095ee2b19811a99) | 6 | Real embedded Tomcat: unauthenticated cert accepted & requested, TLS 1.2/1.3 negotiated, BCJSSE actually serving, nothing requested when off. |
| [MtlsDisabledTokenEndpointMockMvcTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-648bfdfb2c79e8d8f39bb8166d9073ba0492e30d947bc4a044fe288ce250d754) | 8 | **The off-switch suite:** endpoint 404 (default zone and both zone-addressing modes), registration API rejects TLS config, discovery advertises nothing, mapper filter not registered, a previously-persisted mTLS client cannot obtain a bound token (E8). |
| [MtlsFlagConsistencyMockMvcTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-bf34ff944d36ec588a2ba3f93271b3febc3d697662ed800f973665433f1ca8bd) | 1 | `uaa.mtls-enabled=1` must not half-enable the feature. |
| [MtlsTokenEndpointHardeningMockMvcTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-f5282431e505c64daf04b36d03bcf4f6e45f8f52ee6d0075c94ea4309b1ed2c8) | 39 | End-to-end security matrix in nested groups: credential confusion, grant types, validation failures, claim mapping/forgery, cert↔client binding (§2.1.2), `cnf` via introspect/check_token (JWT+opaque), CA rotation, POST-only, RFC 8707 resources, descendant-path routing bypass, discovery when on. |
| [MtlsTokenEndpointMockMvcZonePathTests.java](https://github.com/cloudfoundry/uaa/pull/4076/files#diff-5a46b5bfa04e95c07cda09dc0e4b2a64eb929f5a93d5e6abb6a269c66f875cfe) | 7 | Zone isolation in both zone-addressing modes: own-zone issuance and issuer, cross-zone clients unusable, per-zone CA for the same client id, zone-specific alias. |

---

*Generated from `git diff 6cc037111..HEAD` (develop merge-base); docs under `docs/PR 4076 Thoughts/` are excluded from
all four sections. Companion documents: `pr4076-develop-merge-evaluation.md` (findings M1–M2, L1–L4),
`pr4076-security-review.md`, `pr4076-backwards-compatibility-audit.md`, `pr4076-mtls-enabled-flag-audit.md`.*
