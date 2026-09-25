# RFC 8705 `tls_client_auth` vs. workload-identity federation: understanding Ruben's use case

Context: after the RFC 8705 §2.1.2 subject-binding hardening in `review/pr3792-fix`
(PR #4076), Ruben felt the fix over-constrained the use case behind his original
implementation ([PR #3972](https://github.com/cloudfoundry/uaa/pull/3972) /
[design gist](https://gist.github.com/rkoster/80fabc4994d105b158df608c77afdd2c)).
This doc captures the discussion working out why.

## 1. What use case was Ruben actually going after?

**PR [#3972](https://github.com/cloudfoundry/uaa/pull/3972)** implements RFC 8705
mutual-TLS client authentication for CF app instance identity: a new
`/oauth/mtls/token` endpoint lets a CF app instance exchange the short-lived
X.509 certificate Diego already gives it (`instance.crt`/`instance.key`) for a
UAA JWT carrying verified `app_guid`/`space_guid`/`org_guid` claims — no secret,
no user credential.

**The [design gist](https://gist.github.com/rkoster/80fabc4994d105b158df608c77afdd2c)**
("Diego instance-identity certificates and RFC 8705 tls_client_auth subject
binding") lays out the underlying tension: UAA used a **shared OAuth client**
trusting Diego's instance-identity CA wholesale, deriving `app_guid`/`space_guid`/
`org_guid` from whatever certificate subject shows up on a given request. That's
a *population* trust model — "any cert from this CA, for any app, authenticates
as this one client; claims are derived per-request." But RFC 8705 §2.1.2 requires
exactly one subject-binding parameter, registered per client, matched by exact
DN/SAN equality — a *one client = one fixed subject* model. Diego mints a new
cert with a new instance GUID in the CN/SAN every time a container is replaced,
so a client bound to that exact value breaks on every restart; a client with no
real subject constraint isn't really doing §2.1.2 binding at all.

Our hardening (`TlsClientAuthSubjectMatcher`, `ClientAdminEndpointsValidator`)
enforces §2.1.2 correctly — it closed a real impersonation risk where a loosely
matched client could let one app instance's cert authenticate as another. The
cost is that Ruben's shared-client, CA-federation convenience model no longer
works, because it was never fully §2.1.2-conformant to begin with — it borrowed
the endpoint and wire format but not the per-client exact-subject semantics that
make the method secure.

Two non-exclusive ways forward were discussed:

1. **One client per app**, subject-bound to a *stable* field (e.g. an OU carrying
   `org_guid`/`space_guid`/`app_guid`, which doesn't change across container
   restarts — only the CN/instance-GUID rotates). Stays fully RFC 8705-conformant.
2. **Stop calling the shared-CA/population model `tls_client_auth`** — build it
   as its own, clearly-labeled mechanism instead of layering it onto §2.1.2's
   exact-subject guarantee. (This turned out to be the direction Ruben actually
   took — see §4 below.)

## 2. How do AWS/GCP/K8s workload-identity federation avoid this problem?

These systems keep the same fundamental constraint — a relying party still
matches on a subject-like claim, per configured trust policy — but structure it
so rotation and population trust don't compromise security:

- The identity provider (GitHub Actions, a K8s cluster, GCP) issues a **signed
  JWT** with a narrow, IdP-controlled claim set (e.g. GitHub Actions:
  `sub: repo:org/repo:ref:refs/heads/main`; K8s: `sub:
  system:serviceaccount:ns:name`). Nothing downstream can forge these.
- Every such token carries an **`aud` scoped to the specific relying party**
  (a specific AWS role ARN, a specific GCP workload identity pool/provider),
  so a token minted for one consumer can't be replayed against a different one.
- The relying party verifies the signature against the IdP's JWKS, checks
  `aud`, then evaluates a **trust-policy condition** against the claims —
  exact match (`StringEquals`) or an explicit wildcard (`StringLike:
  repo:org/*`) if population trust is deliberately wanted.

The properties that make this safe, mapped back to the UAA case:

1. **The matched claim is chosen to be stable per logical principal, not per
   credential.** A K8s service account's `sub` doesn't change when the pod
   restarts — only the token's signature/expiry does. Direct analogue: bind
   UAA's subject match to `org_guid`/`space_guid`/`app_guid`, not to Diego's
   per-container instance GUID.
2. **The claim is cryptographically unforgeable and audience-scoped** — "trust
   the CA" doesn't mean "trust anything with that signature for any purpose."

This pattern *does* still fail in the wild when the wildcard condition is
written too broadly — e.g. GitHub-Actions-to-AWS trust policies scoped to
`repo:org/*` without a `ref:` constraint have let arbitrary PR branches/forks
assume production IAM roles. That's the same failure class our UAA review
closed: a match broader than the person configuring it realized.

## 3. What does Ruben believe the app will do with the token?

From PR #3972: the app is meant to present the UAA-issued JWT to something
**outside CF** — cloud-platform workload-identity federation (AWS, GCP, Azure)
or any other OIDC-aware relying party — to obtain real credentials or access,
without ever holding a long-lived secret.

Flow: Diego gives the app instance a short-lived mTLS cert → the app trades it
at `/oauth/mtls/token` for a UAA JWT with `app_guid`/`space_guid`/`org_guid`
claims → the app presents *that* JWT to e.g. AWS STS
`AssumeRoleWithWebIdentity` or a GCP Workload Identity Federation pool, which
trusts UAA as an OIDC issuer (via UAA's discovery/JWKS endpoint) and scopes
access via its own trust-policy condition on those claims.

In other words, **UAA plays the OIDC identity-provider role** in the same
chain as GitHub Actions → AWS or K8s → GCP: it isn't the final authorization
decision-point, it converts an ambient platform credential (the Diego cert)
into a portable, verifiable identity assertion. The fine-grained authorization
decision is meant to live downstream, at the relying party's trust policy —
which is exactly why the shared-client/population model felt natural to
Ruben: IdPs in that pattern don't pre-register one client per principal either.

## 4. How would a per-app UAA client actually get registered in a CF foundation?

**If UAA did per-app registration**, the mechanics would mirror CF's existing
dynamic-client-provisioning pattern: a trusted system component holding a UAA
client with `clients.admin`/`clients.write` calls `/oauth/clients` on someone
else's behalf, reacting to CAPI's app-create/app-delete lifecycle. This already
exists for service brokers —
[cloud-gov/uaa-credentials-broker](https://github.com/cloud-gov/uaa-credentials-broker)
provisions/deprovisions UAA clients per service instance, and CAPI is
configured with a UAA client authorized to create `dashboard_client`s for
SSO-enabled brokers (see
[Managing Service Brokers](https://docs.cloudfoundry.org/services/managing-service-brokers.html)).
The per-app equivalent: on first app creation, create a client with
`client_id = app_guid`, subject binding on the stable OU field, CA = Diego's
instance-identity CA; delete it on app deletion. Since `app_guid` is stable for
the app's lifetime, this fires once per app, not per container.

**But Ruben appears to have already moved past that idea.** A separate, more
recent PR, [#3968 "feat(spiffe): JWT-SVID signing endpoint (RFC
UAA-SPIFFE-001)"](https://github.com/cloudfoundry/uaa/pull/3968), solves the
same problem with no per-app client registration at all:

- **One shared client** ("SPIFFE Agent") authenticates to a new `POST
  /jwt-svid/sign` endpoint via ordinary `client_credentials` — a single,
  boring, pre-registered client with no population-matching problem.
- The **app's Diego instance-identity certificate is passed as request data**,
  not used as the mTLS transport-layer credential — so it's never subject to
  RFC 8705's per-client exact-subject-binding requirement at all.
- UAA verifies that certificate against the configured CA, checks a
  **proof-of-possession signature** (proving the caller currently holds the
  private key, preventing replay of a captured cert), and parses
  `org_guid`/`space_guid`/`app_guid` out of the cert's OUs.
- It mints an RS256 **JWT-SVID**, verifiable offline against UAA's
  `/token_keys`, with a **caller-controlled `aud`** — explicitly solving the
  audience-scoping limitation of UAA's normal OAuth flow (where `aud` comes
  from client metadata and can't be freely set), which is exactly the
  audience-binding property that keeps AWS/GCP/K8s federation safe (§2 above).

This is Ruben's own resolution of the tension: split "authenticate the caller"
(boring, shared, fully §2.1.2-conformant client) from "attest the workload's
identity" (a purpose-built endpoint with its own proof-of-possession and
audience-scoping, entirely outside the mTLS-authentication path). Structurally
the same shape as SPIFFE/SPIRE (workload attestation is separate from the
SPIRE Server's own client identity) and the GitHub-Actions-to-AWS model — it
sidesteps the RFC 8705 subject-binding constraint rather than fighting it.

## Sources

- [PR #3972 — feat: RFC 8705 mutual-TLS client authentication for CF app instance identity](https://github.com/cloudfoundry/uaa/pull/3972)
- [Design gist — Diego instance-identity certificates and RFC 8705 tls_client_auth subject binding](https://gist.github.com/rkoster/80fabc4994d105b158df608c77afdd2c)
- [PR #3968 — feat(spiffe): JWT-SVID signing endpoint (RFC UAA-SPIFFE-001)](https://github.com/cloudfoundry/uaa/pull/3968)
- [PR #4075 — Review of 3972 by fhanik](https://github.com/cloudfoundry/uaa/pull/4075)
- [cloud-gov/uaa-credentials-broker](https://github.com/cloud-gov/uaa-credentials-broker)
- [Managing Service Brokers | Cloud Foundry Docs](https://docs.cloudfoundry.org/services/managing-service-brokers.html)
