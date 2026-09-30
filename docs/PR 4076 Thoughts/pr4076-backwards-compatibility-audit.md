# Backwards-compatibility audit — every test change in PR #4076 vs `cloudfoundry/develop`

The question this answers: **does this PR change or remove any test that existed before it?** A
modified or deleted pre-existing test is the cheapest available signal that behaviour changed, so
every such change is either reverted (with the new behaviour covered separately) or justified here.

Method: diff the fork point against the branch tip, restricted to test sources.

```bash
MB=$(git merge-base cloudfoundry/develop HEAD)
git diff --name-status $MB HEAD -- '*/src/test/*'
git diff --numstat   $MB HEAD -- '*/src/test/*' --diff-filter=M
```

## 1. Headline numbers

| | Count |
|---|---|
| Test files **added** | 18 |
| Test files **modified** | 21 |
| Test files **deleted** | **0** |
| Test files **renamed** | **0** |
| Removed lines across all modified test files | **20** |
| `@Test` / `@ParameterizedTest` / `@Nested` / `@DisplayName` removed or renamed | **0** |

That last row is the important one and it was checked directly, not inferred:

```bash
git diff $MB HEAD -- '*/src/test/*' | grep '^-' | grep -vE '^---' \
  | grep -E '@Test|@ParameterizedTest|void [a-zA-Z_]+\(|@DisplayName|@Nested'
```

The only match in the whole PR is one `@TestPropertySource` line, which was replaced by a superset
of itself. **No pre-existing test case was deleted, renamed, or disabled.** Everything else is
additive, which leaves 20 removed lines as the entire surface of this audit.

## 2. The 20 removed lines, categorised

### 2.1 Changed expectations — two behaviour changes, now reverted

Three test classes were switched to `uaa.mtls-enabled=true` and their assertions updated, which
quietly removed the regression tests for the **default** (mTLS-off) discovery document:

| File | What it had asserted |
|---|---|
| `OpenIdConnectEndpointsMockMvcTests` | `token_endpoint_auth_methods_supported` is exactly the three secret/JWT methods |
| `OpenIdConnectEndpointsMockMvcZonePathTests` | the same, per zone, in both zone-addressing modes |
| `model/.../OpenIdConfigurationTests.defaultClaims` | the same, at the model level |
| `model/.../OpenIdConfiguration.json` | the serialized discovery document |

Root cause found while auditing this, and it is a real defect rather than just a test edit:

```java
// OpenIdConfiguration — the overload that predates RFC 8705 support
public OpenIdConfiguration(final String contextPath, final String issuer) {
    this(contextPath, issuer, true);   // <- defaulted mTLS ON
}
```

The pre-existing two-argument public constructor had been made to default `mtlsEnabled = true`, so
**the same call now produced a different discovery document**: `tls_client_auth` advertised in
`token_endpoint_auth_methods_supported` and `tls_client_certificate_bound_access_tokens: true`. Two
problems at once — a silent behaviour change to an unchanged public signature (a caller compiled
against it cannot know a new capability exists), and a **fail-open default**, since any code path
that forgot to pass the flag would advertise mTLS on a deployment that has it switched off. The
product default is `uaa.mtls-enabled:false`.

**Resolution — restored (option a).** The default is now `false`, matching pre-PR output exactly and
failing closed. Verified that production only ever calls the three-argument form
(`OpenIdConnectEndpoints:41`), so nothing in the server relied on the old default. The original
assertions were restored in all four files, and the two MockMvc classes now additionally assert
`getMtlsEndpointAliases()` is **null** on a default deployment — a stronger guarantee than they had
before, and the thing the previous edit had removed.

The mTLS-enabled shape was never uncovered by this revert: it is asserted by
`MtlsTokenEndpointHardeningMockMvcTests`, `MtlsTokenEndpointMockMvcZonePathTests` (including the
zone-path form of the alias), `OpenIdConnectEndpointsTest`, and its absence when disabled by
`MtlsDisabledTokenEndpointMockMvcTests` (E3/E6). A new model test,
`theConstructorWithoutAnMtlsFlagAdvertisesNoMtlsSupport`, pins the restored default so it cannot
drift again.

Net effect on the wire: the discovery document gains exactly one field for a default deployment,
`"tls_client_certificate_bound_access_tokens": false`. Additive, and RFC 8705 §3.3 defines the
metadata as defaulting to `false` when omitted, so its meaning is unchanged for every existing
client.

### 2.2 `OpenIdConnectEndpointDocs` — restored, with the new fields documented as conditional

This docs class had also been switched to `uaa.mtls-enabled=true`, which meant the **published**
example discovery document showed `mtls_endpoint_aliases` — a field the great majority of
deployments do not serve. (The `ui_locales_supported` line in the diff is a false alarm: only a
comma was added to it.)

**Resolution — restored, and the change documented instead.** The class is back on the default, so
the published example is what most deployments actually return. The two RFC 8705 fields are still
documented: `tls_client_certificate_bound_access_tokens` as always-present, and
`mtls_endpoint_aliases.token_endpoint` as `optional(null).type(STRING)` with its conditionality
stated in the description. RestDocs needs the explicit `type` because it cannot infer one for a
field absent from the payload.

### 2.3 `TokenEndpointDocs` — kept, justified by measurement (option b)

The one config change on an existing test that was **not** reverted. `uaa.mtls-enabled=true` is
needed for the whole class because the new mTLS example cannot document an endpoint the deployment
has not enabled.

This is load-bearing in a non-obvious way: enabling mTLS registers `MtlsClaimsEnhancer`, making
`uaaTokenEnhancers` non-empty, and `UaaTokenServices` takes a different code path when that list is
non-empty — which is exactly how the `granted_scopes` leak found earlier on this branch happened.

So it was measured rather than argued. Snippets were generated with mTLS on and off and compared:

- documented examples compared: **29**
- examples whose response JSON key set changed: **0**
- documented field/parameter tables that differ: **0**

Only randomised values (client ids, JWTs, timestamps) differ. No other published example is
affected. The reasoning and the fallback (move the example to its own docs class if the enhancer ever
contributes claims for non-`tls_client_auth` callers) are recorded in the class javadoc, where
someone changing it will see them.

### 2.4 Mechanical constructor updates — 11 lines, no assertion touched

Five production classes gained a constructor parameter (`mtlsEnabled`, or a `TlsClientAuthentication`
collaborator), so test call sites were updated:

`ClientAdminEndpointsValidator`, `ClientAdminBootstrap` (×5 call sites),
`ClientDetailsAuthenticationProvider`, `ZoneEndpointsClientDetailsValidator` (which also dropped an
`@InjectMocks` in favour of explicit construction).

No assertion was changed and no test case lost. Each class now has a single public constructor, so
the old signature is gone — **source-incompatible for anyone constructing these directly**. They are
internal Spring-wired components of the server, not part of the model/API surface, and no
deprecated overloads were added rather than carry shims for a case that does not exist in practice.
Recorded here because it is a real, if low-risk, API change: anyone compiling against
`cloudfoundry-identity-server` and instantiating these by hand must add the new argument.

### 2.5 One weakened assertion, deliberately

`UaaClientDetailsTest`: `assertThat(uaaClientDetails.hashCode()).isPositive()` →
`.isNotZero()`.

Adding a field to `hashCode()` can make the result negative. `isPositive()` asserted something
`Object.hashCode()` has never promised, so restoring it would re-break on the next field added to
the class. `isNotZero()` is the honest form of the same smoke test. No behavioural contract is
involved; `equals`/`hashCode` consistency is covered by the surrounding tests.

## 3. Intentional behaviour changes (not test-detectable, listed for completeness)

These change behaviour by design. None was found by the test-diff above — the tests for them are all
new — but a compatibility review should state them:

| Change | Compatible? | Notes |
|---|---|---|
| A `tls_client_auth` client must register exactly one RFC 8705 §2.1.2 subject value | **No — deliberate** | A client configured with `tls-client-auth-ca` alone is now refused. The old "compliant" config was the vulnerable one — see `pr3972-vs-pr3792-fix-comparison.md` §3. Only affects a config shape that never shipped in a release. |
| `/oauth/mtls/token` is POST-only (405 + `Allow: POST`) | Yes, in practice | GET was inherited from `/oauth/token`, never documented for this endpoint, and a GET token request leaks parameters into logs. |
| Paths below `/oauth/mtls/token` now return 404 | Yes | They were only reachable via the routing bypass in `pr4076-security-review.md` §1; nothing legitimate is served there. |
| `token-endpoint-auth-method` no longer rejected in `additionalInformation` | **Restores** compatibility | PR #3972 had broken create/update for every client carrying that unrelated key. |
| New `tls-client-auth-allowed-resources` key; `resource` parameter at the mTLS endpoint | Yes — additive | Absent config behaves exactly as before; `resource` is only honoured for clients that opt in. |
| Discovery gains `tls_client_certificate_bound_access_tokens` | Yes — additive | Present as `false` by default; RFC 8705 §3.3 treats omitted as `false`. |

## 4. Verification

- Full unit suite green after the restorations (counts in `SESSION-HANDOFF.md` §6).
- `./gradlew generateDocs` succeeds; the discovery example is back to the default-deployment shape
  (no `mtls_endpoint_aliases` in the example body) while both RFC 8705 fields remain in the field
  table.
- Model, discovery and mTLS suites run green individually.

## 5. Conclusion

No pre-existing test was deleted, renamed or disabled anywhere in this PR. Of the 20 removed lines,
one group hid a genuine backwards-compatibility break — the two-argument `OpenIdConfiguration`
constructor silently changing its output, and failing open while doing it — which is now restored and
pinned by a new test. One config change is kept and justified by measurement. The rest are
mechanical constructor updates and one assertion that was never a real contract.

The remaining knowingly-incompatible change is the RFC 8705 §2.1.2 subject-binding requirement, which
is the security fix at the heart of this branch and is documented as a deliberate trade-off.
