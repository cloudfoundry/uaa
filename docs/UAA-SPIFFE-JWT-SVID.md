# UAA as a SPIFFE identity server (JWT-SVID)

UAA can issue [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/overview/) JWT-SVIDs to Cloud
Foundry workloads, so an app instance can prove *what it is* to a relying party outside the
foundation without ever holding a long-lived secret. This implements RFC UAA-SPIFFE-001 and is
exposed as a single endpoint, `POST /jwt-svid/sign`.

The feature is **off by default** and activates only when `uaa.spiffe.instance_identity_ca` is set.

## What problem this solves

Cloud Foundry already issues every app instance a short-lived X.509 certificate — `instance.crt`
and `instance.key`, mounted into the container by the Diego cell and signed by the foundation's
instance-identity CA. That certificate is excellent proof of identity *inside* the foundation, but
nothing outside Cloud Foundry knows how to consume it.

Meanwhile AWS, GCP, Azure and most modern OIDC-aware services all accept the same shape of
credential: a short-lived, signed JWT from a trusted issuer, whose claims the relying party matches
against its own trust policy. That is exactly how GitHub Actions authenticates to AWS, and how a
Kubernetes service account authenticates to GCP.

This feature bridges the two. UAA verifies the platform-issued certificate it already trusts and
mints a JWT-SVID that any OIDC-aware relying party can verify offline against UAA's `/token_keys`.
The app never stores a cloud credential.

## SPIFFE concepts, briefly

- A **trust domain** is the name of an identity issuance authority, e.g. `cf.example.com`.
- A **SPIFFE ID** is a URI identifying one workload within a trust domain.
- An **SVID** (SPIFFE Verifiable Identity Document) is a signed document asserting a SPIFFE ID.
  SPIFFE defines two kinds: X509-SVIDs and **JWT-SVIDs**. This feature issues the latter.

UAA formats CF workload SPIFFE IDs as:

```text
spiffe://<trust-domain>/cf/org/<org_guid>/space/<space_guid>/app/<app_guid>/process/<process_type>
```

Every path segment is validated against the
[SPIFFE ID specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md),
which permits only `[a-zA-Z0-9.-_]` per segment. This matters: three of those segments come from
the certificate and one from the request body, and all four are concatenated into an identifier
that relying parties authorize on.

## The two identities involved

The most important thing to understand about this endpoint is that **two separate identities** are
in play, and neither one alone is sufficient.

| | Who | How it is established |
|---|---|---|
| **Caller** | The SPIFFE Agent | HTTP Basic client credentials; the UAA client must hold the `uaa.resource` authority |
| **Subject** | The workload the SVID is for | The `instance_certificate` in the request body, plus a proof-of-possession signature |

The agent's own credentials authorize it to *use the endpoint*. They do not authorize it to mint
any particular identity. Which identity gets issued is determined entirely by the certificate
presented and by proof that the caller holds that certificate's private key.

This split is what makes a single shared agent client safe. It is also why this design sidesteps
the RFC 8705 constraint that one OAuth client corresponds to one fixed certificate subject: the
workload's certificate is request *data* that UAA verifies, not the transport-layer credential
that authenticates the client.

## Request flow

1. The SPIFFE Agent authenticates to UAA with HTTP Basic client credentials.
2. UAA validates the request fields: `process_type` must match `[A-Za-z0-9_-]{1,63}`, and
   `audience` must be non-blank, at most 512 characters, and free of control characters. Both
   constraints exist because these values end up in a SPIFFE ID path and in a newline-delimited
   signed message respectively.
3. UAA parses `instance_certificate` and verifies it: it must be currently time-valid, must be
   signed directly by the configured CA, must not be self-issued or a CA certificate itself, and
   the CA must itself be time-valid.
4. UAA extracts the `organization:`, `space:` and `app:` OU attributes from the certificate
   subject. Each must appear exactly once.
5. UAA composes the SPIFFE ID and validates every segment against the SPIFFE ID specification.
6. UAA verifies the proof of possession — see below.
7. UAA signs and returns the JWT-SVID.

### Proof of possession

An instance certificate is **not a secret**. It is sent in the clear during TLS handshakes and
forwarded by Gorouter in `X-Forwarded-Client-Cert` headers. Anyone who has merely *seen* a
workload's certificate must not be able to obtain that workload's identity.

So the caller must also sign a message proving it holds the matching private key. The message is
the three fields joined by newlines:

```text
<spiffe_id>\n<audience>\n<timestamp>
```

signed with `SHA256withECDSA` or `SHA256withRSA` (matching the certificate's key type) and
base64-encoded. Because the SPIFFE ID and the audience are inside the signed message, neither can
be swapped after the fact — a signature obtained for one audience cannot be reused for another.

The `timestamp` must be within `uaa.spiffe.pop_freshness_seconds` of UAA's clock in either
direction.

## The issued token

```json
{
  "iss": "https://uaa.example.com/oauth/token",
  "sub": "spiffe://cf.example.com/cf/org/<org>/space/<space>/app/<app>/process/web",
  "aud": "https://iam.example.com/...",
  "iat": 1730000000,
  "exp": 1730003600,
  "jti": "…",
  "cf": {
    "org_id": "…",
    "space_id": "…",
    "app_id": "…",
    "process_type": "web"
  }
}
```

The SPIFFE JWT-SVID specification requires `sub` to be the SPIFFE ID, and requires both `aud` and
`exp` to be present — validators MUST reject tokens lacking either. The `cf` claim is a UAA
extension carrying the same GUIDs in a form a relying party can match on directly without parsing
the SPIFFE ID path.

The token is signed with UAA's **active token-signing key** and carries UAA's normal issuer, so a
relying party verifies it exactly as it would any UAA-issued JWT, against `/token_keys`.

### Caller-controlled audience

Unlike UAA's OAuth flows — where `aud` is derived from client metadata — the caller chooses the
`audience` here. This is deliberate and necessary: workload identity federation requires the token's
audience to match whatever the relying party expects (a GCP workload identity pool resource name, an
AWS role, and so on).

The SPIFFE specification "strongly recommends" a single audience per token to limit replay scope,
and UAA enforces exactly one.

## Relationship to UAA access tokens

A JWT-SVID is signed with the same key, carries the same `iss`, and has the same `typ` and `kid`
header as a real UAA access token. The claim set is the only thing distinguishing the two
populations: a JWT-SVID carries no `client_id`, `cid`, `scope` or `user_id`, which is why UAA's own
introspection rejects one. Relying parties should not treat "signed by UAA" as sufficient — check
that `sub` is a `spiffe://` URI, and check `aud`.

## Configuration

```yaml
uaa:
  spiffe:
    # Required. Setting this activates the feature.
    instance_identity_ca: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
    # Required. Lowercase, [a-z0-9.-_] only. Validated at startup.
    trust_domain: cf.example.com
    # Optional, defaults below.
    jwt_svid_ttl_seconds: 3600
    pop_freshness_seconds: 60
    pop_enabled: true
```

See [UAA-Configuration-Reference.md](UAA-Configuration-Reference.md) for the full description of
each property.

Notes for operators:

- Only a single certificate is read from `instance_identity_ca` — the first PEM object. Instance
  certificates must be signed **directly** by this CA; intermediate-issued chains are not supported.
- `trust_domain` is not itself a feature gate, so UAA validates it at startup and refuses to boot
  if it is missing or non-conformant. Otherwise every workload would be issued an identity under
  `spiffe://null/`.
- **Do not set `pop_enabled: false` outside local development.** It skips proof of possession
  entirely, which means any client holding `uaa.resource` can obtain an SVID for any workload just
  by presenting that workload's (public) certificate. UAA logs a warning at startup when it is off.

## Operational considerations

- **Token lifetime.** The default `jwt_svid_ttl_seconds` is 3600. JWT-SVIDs are bearer tokens and
  the SPIFFE specification recommends "an aggressive value for the `exp` claim"; SPIRE's own default
  is 5 minutes. Consider lowering this.
- **Replay within the freshness window.** UAA does not track proof-of-possession nonces, so a
  captured `pop_signature` can be replayed until its `timestamp` falls outside
  `pop_freshness_seconds`. Keeping that window small limits the exposure.
- **Authority granularity.** The endpoint requires `uaa.resource`, which is a broad authority
  shared with resource servers that call `/introspect` and `/check_token`. Any client holding it can
  reach this endpoint, though it still cannot mint an identity without a valid proof of possession.
- **Revocation.** Issued SVIDs are not revocable before expiry, and the instance certificate is not
  checked against a CRL or OCSP responder.
- **Rate limiting.** `/jwt-svid/sign` is covered only by UAA's default global limiter bucket. Both
  signature verification and JWT signing are CPU-bound; consider a dedicated limiter mapping. See
  [UAA-Rate-Limiting.md](UAA-Rate-Limiting.md).
- **Identity zones.** The SPIFFE configuration is global rather than per-zone, while the issued
  token's `iss` follows the zone the request arrives in.

## References

- [SPIFFE overview](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [SPIFFE ID specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
- [JWT-SVID specification](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md)
- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
