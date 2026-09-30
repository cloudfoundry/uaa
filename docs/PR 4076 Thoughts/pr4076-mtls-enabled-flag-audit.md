# `uaa.mtls-enabled` audit — does the whole feature switch together?

Prompted by the `OpenIdConfiguration` fail-open default found during the backwards-compatibility
audit: a convenience constructor advertised mTLS regardless of the flag. That raised the obvious
follow-up — is the flag respected *everywhere*, and can anything be half-enabled?

Method: enumerate every production reader of the flag, enumerate every mTLS component, diff the two
lists, and check each ungated component for whether it can act when the feature is off.

```bash
grep -rn "mtls-enabled\|mtlsEnabled" --include=*.java server/src/main uaa/src/main model/src/main
```

## 1. Finding: the flag had two different meanings (fixed)

**Confirmed by test, then fixed.** The flag was read two ways, and they did not agree on what
counts as true:

| Mechanism | Components | Accepts as true |
|---|---|---|
| `@ConditionalOnProperty(name = "uaa.mtls-enabled", havingValue = "true")` | `MtlsClaimsEnhancer`, `mtlsTokenEndpointSecurity` | the literal string `true` only (case-insensitive) |
| `@Value("${uaa.mtls-enabled:false}") boolean` | availability filter, certificate-mapper filter, `ClientAdminEndpointsValidator`, `ZoneEndpointsClientDetailsValidator`, `ClientAdminBootstrap`, `MtlsClientAuthTomcatCustomizer`, `OpenIdConnectEndpoints` | `true`, and also `1`, `yes`, `on` — the environment's `StringToBooleanConverter` |

So `uaa.mtls-enabled=1` switched on the seven and left the two off. Verified with a real Spring
context (`MtlsFlagConsistencyMockMvcTests`, **K1**): the availability filter passed a request for
`/oauth/mtls/token` straight through — the endpoint was being served — while
`MtlsClaimsEnhancer` was absent from the context.

That half-enabled state is worse than either extreme:

- the endpoint is reachable, and discovery advertises `tls_client_auth`,
  `mtls_endpoint_aliases` and `tls_client_certificate_bound_access_tokens: true`;
- but nothing stamps `cnf.x5t#S256`, so tokens issued there are **not** certificate-bound while
  discovery says they are — the exact "tells a resource server the opposite of the truth" failure the
  surrounding code comments are written to avoid;
- and the endpoint has no OAuth security chain of its own, so the path falls through to the catch-all
  browser chain.

Note the asymmetry of the risk: a value like `0`, `no` or `off` is false to *both* mechanisms, so the
dangerous set is only the truthy-but-not-`true` spellings. Values outside both sets (`maybe`) already
fail boot, because the boolean conversion throws.

**Fix.** A single `MtlsEnabledCondition` now gates the two `@Conditional` components, reading the
flag through `Environment.getProperty(key, Boolean.class, false)` — the same conversion service the
`boolean` injection points use. One switch, one meaning. Chosen over the alternatives deliberately:
making the seven `@Value` sites strict instead would have meant changing seven constructor
signatures (the kind of churn §2.4 of the compatibility audit already flags), and silently disabling
a feature an operator asked for is its own surprise.

K1 is written as a consistency assertion rather than a snapshot — it asserts the endpoint's state and
the enhancer's state are *equal*, so it keeps working whichever way a future maintainer resolves the
spelling question.

## 2. Components with no gate — and why each is safe

Three mTLS things are deliberately not gated. Each was checked for whether it can act with the
feature off.

### `UaaTokenEndpoint`'s `@RequestMapping`

Lists `/oauth/mtls/token` unconditionally, so the path resolves to a controller even when the feature
is off. This is the known asymmetry the availability filter exists for, and it is load-bearing enough
that three tests pin it: **E1** (404 in the default zone), **E5** (404 in a non-default zone, both
addressing modes) and the exact-path rule added by the security review. Since the filter runs at
order -290 — after zone-path rewriting, before Spring Security at -100 — a zone-prefixed request is
matched identically.

### `RawPeerCertificateCaptureFilter`

Registered without a gate, so it runs on every request even when mTLS is off. Safe, and left alone
on purpose: all it does is copy the standard `jakarta.servlet.request.X509Certificate` attribute to a
private attribute, and only when the servlet path is the mTLS endpoint or below — which returns 404
anyway when the feature is off. It grants nothing and reads no configuration. Gating it would mean
adding a parameter to its `@Bean` factory method and updating four test call sites for no behavioural
gain; the certificate-mapper filter next to it *is* gated, but for a different and real reason — it
reflectively loads a third-party class, so constructing it couples UAA's ability to boot to that jar.

### `TlsClientAuthentication`

An ungated `@Component`. What keeps it unreachable with the feature off is not the flag but two other
gates: the endpoint 404s, and `ClientDetailsAuthenticationProvider` refuses `tls_client_auth` for any
request that is not on the mTLS path.

That leaves one realistic scenario worth pinning rather than reasoning about — clients registered
while the feature was on, after an operator turns it off. `ClientAdminEndpointsValidator` stops new
ones being created (**E2**), but it cannot un-persist rows already in the database. New test **E8**
covers it: such a client gets 404 at the mTLS endpoint, and at `/oauth/token` it cannot obtain a token
carrying `cnf` or `client_auth_method: tls_client_auth`. It fails closed — by code reading, the
provider refuses it outright, because a client configured for `tls_client_auth` may not present
credentials and may not authenticate off the mTLS path. The side effect is that such a client is
effectively inert until the flag goes back on, which is the safe direction but worth knowing before
an operator flips the switch on a live foundation.

## 3. Full gating inventory

| Component | Gate | Behaviour when off |
|---|---|---|
| `MtlsClientAuthTomcatCustomizer` | `@Value` boolean | returns before touching the connector — no client-certificate request, no BCJSSE switch |
| `mtlsTokenEndpointSecurity` chain | `MtlsEnabledCondition` | bean absent |
| `MtlsClaimsEnhancer` | `MtlsEnabledCondition` | bean absent, so `uaaTokenEnhancers` stays empty and `UaaTokenServices` keeps its pre-feature code path |
| `MtlsEndpointAvailabilityFilter` | `@Value` boolean | 404s the endpoint and everything below it |
| `clientCertificateMapperFilter` | `@Value` boolean | disabled registration; the buildpack class is never loaded |
| `ClientAdminEndpointsValidator` | `@Value` boolean | refuses `tls-client-auth-ca` / `-trusted-proxy-ca` at create/update |
| `ZoneEndpointsClientDetailsValidator` | `@Value` boolean | same, for the zone client API |
| `ClientAdminBootstrap` | `@Value` boolean | same, for BOSH `oauth.clients` |
| `OpenIdConnectEndpoints` | `@Value` boolean | advertises none of the three mTLS metadata fields |
| `OpenIdConfiguration` | constructor argument | conservative default, see the compatibility audit |
| `UaaTokenEndpoint` mapping | none — by design | covered by the availability filter (E1/E5) |
| `RawPeerCertificateCaptureFilter` | none — harmless | copies an attribute for a path that 404s |
| `TlsClientAuthentication` | none | unreachable via the endpoint 404 and the path check (E8) |

No XML or YAML wiring references the feature, so this list is complete.

## 4. Tests added by this audit

- `MtlsFlagConsistencyMockMvcTests` **K1** — the whole feature must switch together, asserted as a
  consistency property under `uaa.mtls-enabled=1`.
- `MtlsDisabledTokenEndpointMockMvcTests` **E8** — a client whose mTLS config predates the flag being
  turned off cannot obtain a certificate-bound token.

Both directions of the discovery metadata were already pinned during the compatibility audit:
**J1** (enabled advertises all three) and **E3**/**E6** (disabled advertises none).
