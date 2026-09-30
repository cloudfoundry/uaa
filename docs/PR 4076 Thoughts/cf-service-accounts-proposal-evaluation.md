# Evaluation — CF Service Accounts for Workload Identity

Source: [rkoster's Service Accounts RFC draft](https://gist.github.com/rkoster/ee2ae127944943707c44f8f6f8b3f83d)

Compared against the two approaches already on the table:

- [PR #4076](https://github.com/cloudfoundry/uaa/pull/4076) / [#3972](https://github.com/cloudfoundry/uaa/pull/3972)
  — RFC 8705 mutual-TLS client authentication (branch `review/pr3792-fix`)
- [PR #3968](https://github.com/cloudfoundry/uaa/pull/3968) — SPIFFE JWT-SVID signing endpoint

## 1. What it proposes

A **service account** becomes a first-class CF object: a stable, foundation-unique name
(`payments-worker`), owned by an org, bindable to one or more apps. When an app is bound, Diego adds
**one derived DNS SAN** to that app's instance certificate:

```text
payments-worker.svc.identity
```

CAPI then maintains a managed UAA client whose ID is `cf:service-account:payments-worker`, bound via
RFC 8705 §2.1.2 to exactly that DNS SAN. The app authenticates with its existing instance
certificate at the mTLS token endpoint and receives a certificate-bound
(`cnf.x5t#S256`) `client_credentials` token.

## 2. Why this is a genuinely different approach

The other two approaches are both *workarounds for the same obstacle*. RFC 8705 §2.1.2 binds one
client to **one fixed certificate subject value**, but Diego mints a new certificate with a new
instance GUID in the CN/SAN every time a container is replaced. So:

- **#3972's original design** wanted one shared client to cover a rotating population of certs —
  which §2.1.2 cannot express, and which is why the hardening work in #4076 felt constraining.
- **#3968** sidesteps §2.1.2 entirely by moving the certificate out of the transport-authentication
  path, treating it as request *data* verified alongside a proof-of-possession signature.

This proposal instead **removes the obstacle**: it introduces a certificate subject value that is
*stable across container replacement*, so §2.1.2 applies exactly as written — one client, one exact
DNS name, no wildcards, no spec-bending. That is the same conclusion we reached earlier (bind on a
stable field, not the ephemeral instance GUID), except that rather than scavenging an existing
stable field like the app-GUID OU, it introduces a purpose-built identifier and gives it a
lifecycle, an owner, and an audit trail.

That is the architecturally correct answer. The cost is that it stops being a UAA change and
becomes a platform program.

### 2.1 What "stable subject" means here

"Subject", in RFC 8705 §2.1.2, means the identifier **inside the X.509 certificate** that UAA
matches against — a subject DN, or a SAN value. It is the answer to "which certificate may
authenticate as this client". It is *not* the OAuth client ID.

A Diego instance certificate carries roughly this today:

```text
CN       = <instance-guid>                                          <- rotates per container
DNS SAN  = <instance-guid>                                          <- rotates per container
IP SAN   = <container-ip>                                           <- rotates per container
OU       = organization:<org-guid>, space:<space-guid>, app:<app-guid>   <- stable per app
```

That rotation is the entire problem. Bind a client to `CN=<instance-guid>` and it breaks the first
time the container is replaced; widen the binding enough to survive replacement and §2.1.2's
exactly-one-exact-value guarantee is gone.

The proposal adds **one further DNS SAN**, derived from the service-account name rather than from
the container:

```text
DNS SAN  = payments-worker.svc.identity
```

UAA then registers `tls_client_auth_san_dns: payments-worker.svc.identity` — a single exact value
that never changes. That is the stable subject.

Note that it is stable in two dimensions at once: **across time** (container churn) and **across
instances**, since every instance of every app bound to the account presents the same value. That is
what allows one OAuth client to legitimately represent a population of workloads — not by loosening
the match, but because the population genuinely shares one identifier.

### 2.2 The stable subject and the reserved client ID are two different mechanisms

These are easy to conflate, and only the first is what makes the design work. Authentication
requires both halves to line up:

1. the presented certificate carries `payments-worker.svc.identity`; and
2. the client being authenticated as — `cf:service-account:payments-worker` — is registered in UAA
   with that SAN as its subject binding.

Half 1 is protected by **Diego**, which issues that SAN only to bound apps. It stops a workload
claiming to *be* something it is not.

Half 2 is protected by the **reserved client-ID prefix**, and it guards a different thing: not who
may present the identity, but who may *define what the name means*. Downstream consumers — CAPI's
resource layer, brokers, Gorouter route policy — authorize on `sub` / `client_id` equal to
`cf:service-account:payments-worker`, so whoever controls that client's registration controls the
scopes and audiences a token bearing that subject can carry. Without the reservation there are two
distinct attacks: squat the name so CAPI cannot create it (and may then adopt an attacker-authored
client), or register it with attacker-chosen scopes so that every app Diego grants the SAN to
authenticates against the attacker's definition.

So the reservation is **not** what makes the subject stable — the SAN is. The stable-subject idea
would work under any client-ID naming scheme. The prefix is chosen so that the namespace is
recognisably platform-managed, protectable by a single rule, and identifiable by downstream policy.
(The draft's "at most 82 characters" note is just `cf:service-account:` at 19 characters plus a
63-character maximum name, checked against client_id length limits.)

One consequence to keep in view: UAA client IDs are unique **per identity zone**, not per
foundation. "Reserve the prefix" and "foundation-wide unique names" are therefore entangled, which
is why the zone decision sits inside 5.1 rather than being treated separately.

## 3. How it would function end to end

1. An operator/developer creates the account: `POST /v3/service_accounts` with a name and owning org.
   Names are 3–63 chars, immutable, foundation-unique; deletion leaves a **tombstone** so a name can
   never be reclaimed.
2. CAPI creates the managed UAA client `cf:service-account:<name>`, configured with the foundation
   instance-identity CA trust bundle and `tls_client_auth_san_dns: <name>.svc.identity`.
3. An app is bound: `PATCH /v3/apps/{guid}/relationships/service_account`.
4. Diego (BBS/rep/executor) issues that app's instance certificates with the extra DNS SAN, plus a
   **non-critical CF certificate extension** carrying account UUID, app-binding UUID and binding
   revision. The app keeps its own private key, instance GUID CN/SAN, IP SAN and org/space/app OUs.
   **Staging** task certificates deliberately exclude the account SAN.
5. The app calls the mTLS token endpoint with its instance certificate. UAA matches the DNS SAN
   against the registered binding, performs a **live binding check** against a CAPI-owned
   binding-status authority (≤60 s cache, fail closed), and issues a token with `cnf.x5t#S256`,
   platform-owned claims (account, app, space, org, instance, binding revision), and an `aud`
   selected from a curated list of authorized targets. Target lifetime: **≤5 minutes, and never
   beyond leaf-certificate expiry**.
6. Consumers — CAPI's own resource layer, Gorouter route policy, and service brokers — verify
   issuer, audience and `cnf`, and check the binding revision against active assignments.
7. For services, OSB bind carries `bind_resource.service_account` (name, UUID, issuer, subject,
   client_id, DNS SAN, token profile, binding revision) and the broker returns **non-secret**
   connection metadata: issuer, subject, audience, scopes, discovery URL — no key, no secret, no
   token.

## 4. What already exists versus what is new

This is the part the proposal's own component table understates. Verified against
`review/pr3792-fix`:

### Already implemented by PR #4076

| Proposal requirement | Status in #4076 |
|---|---|
| `tls_client_auth` client authentication method | Done |
| mTLS token endpoint (`/oauth/mtls/token`), gated by `uaa.mtls-enabled` | Done |
| Per-client `tls-client-auth-ca` trust bundle | Done |
| **`tls_client_auth_san_dns` subject binding** | **Done** — `TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS` |
| **Exact canonical DNS matching, no wildcard or suffix matching** | **Done** — `TlsClientAuthSubjectMatcher.sanMatches` compares case-insensitively with no wildcard path, and checks the SAN *type* so a dNSName cannot be satisfied by an email SAN that reads the same |
| RFC 8705 §2.1.2 "exactly one subject binding parameter", fail closed | Done — enforced at registration and at authentication |
| `cnf.x5t#S256` certificate-bound access tokens (§3.1) | Done |
| `tls_client_certificate_bound_access_tokens` + `mtls_endpoint_aliases` discovery (§3.3, §5) | Done |
| mTLS endpoint restricted to `client_credentials` (no user identity claims) | Done |
| Gorouter XFCC / trusted-proxy-CA topology handling | Done |
| Identity-zone isolation of all of the above | Done (zone-path and subdomain covered) |

So the proposal's UAA row — "Exact RFC DNS binding, managed-client namespace, client lifecycle, live
binding check, audience selection, JWT profile" — is roughly **one-third already built**. The
`tls_client_auth_san_dns` binding this design depends on is exactly what #4076 implements, including
the no-wildcard rule the RFC draft calls for. **PR #4076 is a prerequisite for this proposal, not an
alternative to it.**

A per-component breakdown of the remaining work follows in sections 5 and 6.

## 5. Work required in UAA

UAA's share is the smallest of any component — most of the RFC 8705 machinery this design needs is
already merged — but two of the seven items are architectural commitments rather than features.
File references are to `review/pr3792-fix`.

### 5.1 Reserve the `cf:service-account:` client-ID namespace — prerequisite

Without this the whole trust model is a naming convention: anybody able to create a client called
`cf:service-account:payments-worker` *is* that service account. This is the highest-severity item in
the proposal, and the RFC correctly lists it as an open question rather than an assumption.

There is already a mechanism to extend rather than invent.
`ClientAdminEndpointsValidator.reservedClientIds` holds an exact-match set (today just `uaa`) and
raises `"... is a reserved client_id"`. The work is to generalise that from exact match to a prefix
rule, and then:

- Enforce it on **create** in `ClientAdminEndpointsValidator`, and on **delete/update** so a tenant
  cannot remove or repoint a managed client. (Client IDs are immutable in UAA — the ID is the
  primary key — so there is no rename path to guard, which helps.)
- Enforce it in **`ClientAdminBootstrap`** as well, so a `uaa.yml` `oauth.clients` entry cannot
  squat the namespace at boot. This path is separate from the admin API and was the source of a
  validation gap already fixed once on this branch.
- Introduce a **privileged authority** for CAPI's managed-client operations (say `clients.managed`),
  so that holding ordinary `clients.admin` is *not* sufficient to write in the namespace. Otherwise
  any zone admin with `clients.admin` can mint service-account clients in their own zone.
- Decide the **identity-zone rule** at the same time (see 5.8); the namespace is only meaningful
  relative to a zone, because UAA client IDs are unique per zone, not per foundation.

Test shape: validator create/update/delete, the bootstrap path, and both cases per zone.

### 5.2 Live binding check in the token-issuance path — the big one

This is the design's largest UAA commitment, because it creates a **runtime dependency from UAA on
CAPI that does not exist today** (the arrow currently points the other way). Work:

- An authenticated client for the CAPI-owned binding-status authority, verifying the **signed**
  revision payloads.
- A cache with a **≤60 s** validity bound, and **fail-closed** behaviour when freshness expires.
- Read the **binding revision from the new X.509 extension** on the presented certificate and
  compare it against the distributed active revision.
- Placement: after certificate authentication and before token minting — i.e. in the
  `TlsClientAuthentication` / `ClientDetailsAuthenticationProvider` path, or as a gate in
  `MtlsClaimsEnhancer` before claims are assembled.
- New configuration: authority URL, trust material, cache TTL, request timeout.
- Metrics and alerting on check latency, staleness and failure rate — operators need to see the
  difference between "denied" and "could not tell".
- An explicit decision on **degraded mode**: fail-closed is correct for security and means a CAPI
  outage beyond 60 seconds halts service-account authentication foundation-wide.

### 5.3 Audience selection (RFC 8707 resource indicators)

**Update — the base of this is now implemented on `review/pr3792-fix`.** When this evaluation was
written UAA had no `resource` parameter at all. It now has one at `/oauth/mtls/token`, governed by a
per-client allow-list (`tls-client-auth-allowed-resources`), with `invalid_target` as the refusal.
See `docs/UAA-Client-Authentication.md` and the "RFC 8707" commits listed in
`SESSION-HANDOFF.md` §2.

Already done:

- ~~Accept and validate a `resource` parameter at `/oauth/mtls/token`.~~ Done, including RFC 8707 §2
  syntax (absolute URI, no fragment), refusal of more than one `resource` value, and refusal on any
  grant other than `client_credentials`.
- ~~Reject anything not on the list — apps must not be able to name arbitrary audiences.~~ Done, and
  enforced twice: at the endpoint before the grant, and again in `MtlsClaimsEnhancer`. The second
  check is not redundant — a routing bypass defeated the first one, see
  `pr4076-security-review.md` §1.
- ~~Populate `aud` from the selected target.~~ Done.
- ~~Decide the interaction with `tls-client-auth-aud-templates`.~~ Done: configuring both on one
  client is refused at registration, so the footgun cannot be assembled.
- ~~Decide where the target list lives.~~ Done for the non-managed case: the client's
  `additionalInformation`, i.e. written by whoever administers the client.

Still to do for *this* design specifically:

- **Per-target permitted scopes.** The implemented allow-list constrains `aud` only. UAA still
  derives scopes from the client's `scope`/`authorities` with no per-audience notion, so "elevate
  scope" is not yet addressed — a client can request any of its own scopes for any permitted target.
- **A richer target object.** The design wants each target to carry an audience *plus* permitted
  scopes *plus* a token profile; the implemented key is a flat list of URI strings.
- **Whether CAPI writes the list or UAA fetches it.** Still open, and now weighted by the fact that
  the simpler option (CAPI writes into the managed client) is what the existing shape already
  supports.
- **Refusing tenant-authored `aud` mechanisms on managed clients.** Mutual exclusion exists, but
  nothing yet distinguishes a managed client from an ordinary one — that depends on §5.1.

### 5.4 Platform-owned claims

For managed clients, stop honouring tenant-authored `tls-client-auth-claim-mappings` /
`tls-client-auth-sub-template` and instead emit claims the platform vouches for: account name and
UUID, app, space, org, instance, binding revision. Implemented in `MtlsClaimsEnhancer`.

This is worth doing for its own sake. Two confirmed findings on this branch (D2, D3) were exactly
that tenant-authored templates could forge `sub` or assert authentication-context claims such as
`amr`/`acr`. Both are now refused by validation, but platform-owned claims remove the category
instead of policing it.

### 5.5 Token-lifetime clamp

Effective expiry becomes `min(client/zone policy, leaf certificate notAfter, now + 300 s)`. UAA has
no notion of certificate expiry as a ceiling on token lifetime today. Refresh tokens are already
stripped for `client_credentials`, so there is no refresh path to bound.

### 5.6 Certificate-extension parsing

Parse the new non-critical CF extension (account UUID, app-binding UUID, revision). Blocked on the
OID being allocated (see 6.7). Must tolerate its **absence** throughout the rollout window, which
means the fail-closed rule needs a defined answer for "certificate predates the extension".

### 5.7 Bearer-assertion profile — only if external federation stays in scope

A separately enabled, target-specific profile issuing a non-`cnf` token for relying parties that
cannot present or validate mTLS, plus the guard the RFC already calls for: a `cnf`-bound token must
never be silently accepted as proof of possession by such a consumer. This is open question 8 and
the least specified part of the draft.

### 5.8 Identity-zone semantics

Unaddressed by the draft and unavoidable in UAA. Either restrict managed clients and the
service-account flow to the **default zone** (simplest; must be documented as a limitation), or give
names, managed clients and the binding authority a **zone dimension** — in which case
"foundation-wide uniqueness" needs restating as "unique per zone", and every consumer's binding
check needs the zone in its key.

### 5.9 Operational

Audit events for managed-client lifecycle and for service-account token issuance (a gap worth
closing regardless), and a dedicated rate-limiter mapping for `/oauth/mtls/token`, which is
CPU-bound and currently sits in the default global bucket.

## 6. Work required by each Cloud Foundry component

### 6.1 CAPI — the largest share, essentially all new

- **Service-account registry**: `POST/GET/PATCH/DELETE /v3/service_accounts`, with 3–63 character
  names, immutability, foundation-wide uniqueness, and **tombstones** so a deleted name can never be
  reclaimed.
- **App relationship**: `GET/PATCH /v3/apps/{guid}/relationships/service_account`,
  `GET /v3/service_accounts/{guid}/apps`.
- **Use grants** for cross-space binding within the owning org:
  `GET/POST/DELETE /v3/service_account_use_grants[/{guid}]`.
- **Managed-principal mapping**: create, update and delete the `cf:service-account:<name>` UAA
  client, holding whatever privileged credential 5.1 defines. Needs to be reconciling rather than
  fire-and-forget, so a partially applied state self-heals.
- **Binding-status authority**: the signed, revisioned distribution channel consumed by UAA,
  Gorouter and CAPI's own resource layer. This is a new piece of infrastructure, not an endpoint —
  it needs an availability story, key management for the signing material, and a rollout mechanism.
- **Async bind/unbind jobs** with the stated guarantee: an unbind reaches `succeeded` only once its
  deny revision is distributed or earlier authorizations have aged out. Unavailable consumers may
  delay completion but must not silently extend authorization.
- **Role integration** so service accounts can hold roles through the existing mechanism.
- **Certificate-bound JWT verification** in CAPI's own ingress/resource layer: issuer, audience and
  `cnf` checks, plus principal/role resolution for a `cf:service-account:` subject.
- **Audit** across account lifecycle, binding and unbinding.

### 6.2 Diego — BBS, rep, executor

- **Derive and issue the stable DNS SAN** `<name>.svc.identity` on instance certificates for bound
  apps, while retaining the existing instance-GUID CN/SAN, IP SAN, org/space/app OUs, key usages and
  per-instance keys.
- **Emit the new non-critical X.509 extension** carrying account UUID, app-binding UUID and binding
  revision.
- **Typed certificate metadata** plumbed through BBS to rep/executor.
- **Credential refresh and rollout** so a binding change reaches running instances.
- **Exclude the SAN from staging tasks.** This is a sharp edge: a staging container that carried the
  account SAN could mint production tokens. It needs a test, not just a default.
- Runtime **task** certificates inherit the app's binding.

### 6.3 CF CLI

- Account CRUD and bind/unbind commands.
- A role wrapper for assigning roles to a service account.
- An explicit service-account mode for `cf bind-service`, so the identity-based binding is a
  deliberate choice rather than implicit.

### 6.4 Gorouter and route distribution

- **Extract the service-account SAN** from the client certificate.
- A **new route-policy source type** for service-account identity.
- **Live binding check** against the same authority, with the same ≤60 s / fail-closed semantics.
- **Capability-aware rollout**, since routers and route-policy distribution will be at mixed
  versions during upgrade.

### 6.5 Open Service Broker — specification and implementations

This is the only work item **outside the CF project's control**, which makes it schedule risk.

- Agree a **versioned capability** (`service_account_binding` with `supported_token_profiles`) and
  the **`bind_resource.service_account`** request schema with OSB maintainers.
- Broker-side **grant lifecycle**: create the grant at bind, remove it at unbind.
- **Token-target metadata** returned as non-secret connection info — issuer, subject, audience,
  scopes, discovery URL, and no key, secret or token.
- **Client-driver support** so applications can actually consume a JWT-based binding; without
  drivers the feature is unusable in practice even once brokers support it.

### 6.6 Service brokers in the ecosystem (third parties)

Each broker that wants identity-based binding must implement the capability, validate
certificate-bound JWTs, and handle revision-based revocation. Adoption is voluntary and gradual, so
the long-lived-credential path has to keep working indefinitely alongside it.

### 6.7 Cross-cutting and project-level

- **OID allocation** for the new certificate extension through the project's agreed process. This
  blocks Diego issuance and UAA parsing, so it should start early.
- **Reserve the `.svc.identity` suffix**: it is an identifier, not a resolvable name, so it must be
  protected against collision with real DNS and against issuance by anything other than Diego.
- **Rollout ordering**: consumers must tolerate certificates both with and without the SAN and the
  extension for a long window, and the binding authority must exist before any consumer depends on
  it.
- **Governance for foundation-global names**: org-owned but foundation-unique, with tombstones
  preventing reuse, means one org can permanently consume a name another wants — including by
  accident. Needs a name-squatting policy.
- **Documentation**: the residual-access window after unbind (up to ~5 minutes: 60 s revision
  freshness plus token lifetime) and the fact that copied keys cannot be recalled are the real
  security boundary and belong in operator docs.

## 7. Strengths

- **It solves the root cause rather than routing around the spec.** Everything downstream gets
  simpler because the subject is stable: exact DNS matching, one client per identity, no wildcard
  trust, no population semantics.
- **Identity becomes a named, owned, auditable object** with an explicit lifecycle, instead of being
  inferred by parsing certificate OUs at request time.
- **Curated audience targets are a real security improvement** over a caller-chosen `aud`. It
  directly closes the concern that a client with the right authority can mint a token aimed at any
  audience it names — which is the open edge in #3968's design.
- **Platform-owned claims remove a whole vulnerability class.** In the #4076 review, two confirmed
  findings (D2, D3) were precisely that tenant-authored `sub` templates and claim mappings could
  forge a subject or assert authentication-context claims like `amr`/`acr`. If the platform asserts
  these claims, that attack surface disappears rather than needing validation rules.
- **`cnf` is not conflated with proof of possession.** The draft explicitly refuses to let systems
  that cannot validate mTLS treat a `cnf`-bound token as proof of possession, requiring a separate
  opt-in profile. That is a subtle distinction and it is the correct one.
- **Brokers stop handing out long-lived secrets.** The bind response carries only issuer/subject/
  audience/scopes/discovery URL — no key, no secret, no token.
- **It is honest about revocation limits**, stating outright that removing a relationship cannot
  erase a certificate or key an app already copied.

## 8. Risks and concerns, roughly ranked

1. **Client-ID namespace protection is load-bearing and not yet designed.** Until UAA can guarantee
   the `cf:service-account:` prefix is unforgeable by any tenant or zone admin, the entire trust
   model rests on a naming convention. Open question 3 should be answered before anything else is
   built.
2. **The live binding check inverts UAA's dependency direction.** Today CAPI depends on UAA; this
   puts CAPI in UAA's token-issuance path with fail-closed semantics, so a CAPI outage longer than
   the 60-second freshness window stops service-account authentication foundation-wide. That needs
   an explicit availability target and a considered degraded mode; "fail closed" is right for
   security and expensive for availability, and the tradeoff should be a stated decision rather than
   a consequence.
3. **Identity zones are not addressed at all.** The proposal assumes a *foundation-wide* unique name
   and a single managed client per account, but UAA clients are zone-scoped rows and UAA is
   explicitly multi-tenant. Which zone does `cf:service-account:payments-worker` live in? If the
   default zone only, service accounts are unavailable to every other zone and that limitation
   should be stated. If replicated per zone, "foundation-wide uniqueness" conflicts with per-zone
   client namespaces, and the binding-status authority needs a zone dimension. This is a concrete
   gap, not a detail.
4. **Programme scope.** Seven components, two of them outside the CF project's control (the OSB
   specification, and broker implementations). All eight open questions are consensus items rather
   than implementation details. This is multi-team, multi-quarter work versus a single reviewable
   UAA PR.
5. **Certificate-format changes are slow and hard to reverse.** A new X.509 extension needs an OID
   through the project's process, Diego issuance changes, and every consumer must parse it. Rollout
   ordering matters: consumers must tolerate certificates both with and without the extension for a
   long window.
6. **Foundation-global names in a multi-tenant product invite governance problems.** Org-owned but
   foundation-unique, with tombstones preventing reuse, means one org can permanently consume a name
   another org wants — including by accident. Worth a name-squatting policy.
7. **Staging exclusion is a sharp edge.** A staging container that mistakenly carried the account SAN
   could mint production tokens. Good that the draft calls it out; it needs a test, not just a
   default.
8. **`.svc.identity` must be genuinely reserved.** It is an identifier, not a resolvable name, so the
   suffix has to be reserved against collision with real DNS and against issuance by anything other
   than Diego. Non-resolvable DNS SANs also occasionally confuse TLS stacks that try to verify names.
9. **Residual access after unbind is up to ~5 minutes** (60 s revision freshness plus token
   lifetime), and copied keys cannot be recalled. Acceptable, but it is the real security boundary
   and belongs in operator documentation rather than a design footnote.

## 9. Relationship to the other two approaches

| | #4076 (RFC 8705 mTLS) | #3968 (SPIFFE JWT-SVID) | This proposal |
|---|---|---|---|
| Layer | UAA only | UAA only | CAPI + Diego + UAA + CLI + Gorouter + OSB |
| Stable subject? | No — caller must supply one | Not needed (cert is request data) | **Yes — creates one** |
| Who picks `aud` | Client-admin templates | The caller, freely | Curated targets, app selects |
| Claims asserted by | Tenant claim mappings | Certificate OUs | The platform |
| Primary use case | Generic mTLS client auth | External federation (AWS/GCP/Azure) | CF-internal + broker-mediated |
| Status | Implemented, reviewed, hardened | Implemented, reviewed | Draft RFC |

The important thing to notice: **#4076 is a dependency of this proposal, and #3968 partly competes
with it.** If service accounts land, the SPIFFE agent path becomes largely unnecessary for
CF-internal service auth, though it would remain relevant for SPIRE federation interop.

There is also a genuine tension to resolve. #3972's stated motivation was **external** workload
identity federation with AWS/GCP/Azure, which requires the caller to specify an audience the
relying party expects. This proposal deliberately restricts that, and its escape hatch — a
"target-specific bearer assertion profile" — is the least developed part of the draft (open question
8). If external federation is still a goal, that profile needs to be designed, not deferred; if it
is not, the original motivation for #3972 should be revisited explicitly.

## 10. Recommendation

The design is sound and is the right long-term shape. It is not an alternative to the mTLS work
already reviewed — it consumes it.

Worth answering before committing to the programme:

1. **Client-ID namespace protection** (open question 3) — the trust model depends on it.
2. **Identity-zone semantics** — not covered by the draft at all.
3. **Availability target for the live binding check**, and whether fail-closed foundation-wide is
   acceptable.
4. **Whether external federation is still in scope**, which determines if the bearer-assertion
   profile is optional or essential.

A sensible sequencing would be: land #4076 (done), answer 1–4, then build the CAPI registry plus
Diego SAN derivation as the first vertical slice with a single consumer, before taking on route
policy and the OSB specification change.
