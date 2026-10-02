# Getting Started with mTLS Client Authentication (RFC 8705)

This is a hands-on walkthrough for setting up and using `tls_client_auth` mutual-TLS client
authentication: generating certificates, registering a client two different ways (a live API call
and a static config file), requesting a certificate-bound token, verifying it, and the handful of
things that commonly go wrong.

For the complete property reference, error-response table, and the deployment-topology and
compatibility details, see [UAA-Client-Authentication.md](UAA-Client-Authentication.md). This guide
exists to get a working example running end to end; that one exists to answer "what exactly does
this property do."

## Prerequisites

* A UAA instance reachable over **HTTPS**, with `uaa.mtls-enabled: true` set (see Step 1). This is
  not optional: a client certificate is exchanged during the TLS handshake itself, so there is no
  equivalent over plain HTTP. Enabling `uaa.mtls-enabled` reconfigures UAA's *existing* TLS
  connector to request a certificate; it does not create TLS termination for UAA out of nothing —
  if your instance is HTTP-only today, every request to the mTLS endpoint will fail with the same
  "no certificate presented" error forever, with nothing in the logs pointing at the real cause.
  Step 1a below sets up a disposable local instance that already satisfies this, if you don't have
  one handy.
* `openssl`, `curl`, and `jq` on your workstation.
* A client with `clients.admin` (or `clients.write`) authority, to register the mTLS client. The
  examples below use the stock development client `admin` / `adminsecret` — replace with your own
  deployment's admin credentials.
* Whichever CA signed **UAA's own TLS certificate** — not the demo mTLS CA created in Step 2, which
  is unrelated. Export it once, as an *absolute* path (Step 2 `cd`s into a temporary directory, so
  a relative path stops resolving right after that).

Every command below reads `$UAA` and `$UAA_CACERT` — nothing in this guide hardcodes a hostname,
so there is no find-and-replace step. Run this once, before Step 2, and every command from here on
is copy-paste-as-is:

```bash
export UAA=https://localhost:8443/uaa                          # your UAA's own base URL
export UAA_CACERT="$(pwd)/scripts/certificates/CA.crt"          # whatever CA signed ITS https cert
```

The values above are exactly right for the local instance Step 1a sets up (note the `/uaa` context
path). Against any other deployment, set `UAA` to its real base URL and `UAA_CACERT` to an
absolute path for whatever CA issued *that* deployment's HTTPS certificate.

## Step 1 — Enable the feature

`uaa.mtls-enabled` is a single, deployment-wide switch. In `uaa.yml`:

```yaml
uaa.mtls-enabled: true
```

This is connector-wide, not per-endpoint: every TLS handshake to this UAA instance will now ask the
peer for a certificate (without requiring one — plain HTTPS clients are unaffected). Restart UAA
after changing it. See
[the configuration reference](UAA-Configuration-Reference.md#uaamtls-enabled) for exactly what this
flips at the Tomcat layer.

### Step 1a — Running a local test instance over HTTPS (optional)

There is no Gradle task that boots UAA over HTTPS — `bootRun` and the `integrationTest` task's
embedded boot are both plain HTTP. Build the WAR once:

```bash
./gradlew :cloudfoundry-identity-uaa:assemble     # builds uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war
```

Then just run the script:

```bash
./scripts/boot/boot-with-tls.sh
```

That's the whole setup. It generates a throwaway TLS keystore under `scripts/certificates/` the
first time (skipped on later runs, once one exists), boots that WAR directly via `java -jar` with
`server.ssl.enabled=true` and `uaa.mtls-enabled=true` already set, and serves HTTPS on `8443`
(plain HTTP stays up on `8080` too).

Wait for `Started UaaBootApplication` in the console, then confirm both the TLS connector and the
feature flag came up correctly:

```bash
# UAA's own TLS cert is signed by scripts/certificates/CA.crt -- trust it for these checks only;
# it is unrelated to whatever CA you register for tls-client-auth-ca in the steps below.
curl -s --cacert scripts/certificates/CA.crt \
  https://localhost:8443/uaa/.well-known/openid-configuration \
  | jq '{tls_client_certificate_bound_access_tokens, mtls_endpoint_aliases}'
```

```json
{
  "tls_client_certificate_bound_access_tokens": true,
  "mtls_endpoint_aliases": { "token_endpoint": "https://localhost:8443/uaa/oauth/mtls/token" }
}
```

Stop the instance with `kill` on its `java` process's PID when you're done — not the PID of the
script itself, if you backgrounded it with `&`; the script execs `java` as a child process, so the
two PIDs differ. It's an in-memory HSQLDB profile, so nothing persists between runs.

## Step 2 — Create a CA and a client certificate

Everything below is for a throwaway demo CA — in a real Cloud Foundry deployment, the CA is
Diego's instance-identity CA, and you would skip straight to Step 3 using that CA's certificate.

```bash
WORKDIR=$(mktemp -d)
cd "$WORKDIR"

# 1. A self-signed CA.
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout ca-key.pem -out ca-cert.pem \
  -subj "/CN=Demo mTLS CA"

# 2. A client key and certificate signing request.
openssl req -newkey rsa:2048 -nodes \
  -keyout client-key.pem -out client.csr \
  -subj "/CN=mtls-demo-client"

# 3. Sign the client certificate with the CA.
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -days 90 -out client-cert.pem

# 4. The exact subject DN UAA will need to match (RFC 2253 form).
SUBJECT_DN=$(openssl x509 -in client-cert.pem -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
echo "$SUBJECT_DN"
# CN=mtls-demo-client
```

`$SUBJECT_DN` is used as the client's `tls_client_auth_subject_dn` in the next step. RFC 8705
section 2.1.2 requires an authorization server to match a *specific* registered value, not just
"issued by the right CA" — chain validation alone only proves who issued the certificate, not that
it belongs to this particular client. Reading the value out of the certificate itself, rather than
typing it by hand, is what guarantees the two sides agree on formatting; see
["Scoping a client to a specific org/space/app"](UAA-Client-Authentication.md#scoping-a-client-to-a-specific-orgspaceapp)
for the comparison rules.

## Step 3 — Register the client

Two ways to set this up: a live API call, or a static config file. Both accept exactly the same
properties and run through exactly the same validation.

### 3a. Via the client-admin API

First, get an admin access token:

```bash
ADMIN_TOKEN=$(curl -s --cacert "$UAA_CACERT" "$UAA/oauth/token" \
  -u admin:adminsecret \
  -d grant_type=client_credentials \
  -d scope=clients.write \
  | jq -r .access_token)
```

Then register the client. `tls-client-auth-ca` is the trust anchor; `tls_client_auth_subject_dn` is
the one required RFC 8705 §2.1.2 subject binding (exactly one of five parameters is required — see
the [property table](UAA-Client-Authentication.md#configuration) for the other four). No
`client_secret` — the certificate is this client's only credential.

```bash
CA_PEM=$(cat ca-cert.pem)

cat > client.json <<JSON
{
  "client_id": "mtls-demo-client",
  "authorized_grant_types": ["client_credentials"],
  "scope": ["uaa.none"],
  "authorities": ["uaa.resource"],
  "tls-client-auth-ca": $(jq -Rs . <<< "$CA_PEM"),
  "tls_client_auth_subject_dn": "$SUBJECT_DN"
}
JSON

curl -s --cacert "$UAA_CACERT" -X POST "$UAA/oauth/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @client.json | jq .
```

`jq -Rs .` reads the PEM file as a raw string and produces a correctly JSON-escaped value (PEM's
embedded newlines would otherwise break the JSON). A successful response is `201 Created` with the
client's full configuration echoed back, `tls-client-auth-ca` included.

### 3b. Via a config file (`uaa.yml` bootstrap)

The same client, expressed as a BOSH/`uaa.yml` `oauth.clients` entry instead. Every hyphenated
property goes directly under the client's block, unindented relative to each other:

```yaml
oauth:
  clients:
    mtls-demo-client:
      authorized-grant-types: client_credentials
      scope: uaa.none
      authorities: uaa.resource
      tls-client-auth-ca: |
        -----BEGIN CERTIFICATE-----
        ... contents of ca-cert.pem ...
        -----END CERTIFICATE-----
      tls_client_auth_subject_dn: "CN=mtls-demo-client"
```

This is validated at UAA startup with exactly the same rules as the API path — a malformed mTLS
client in this block prevents the bootstrap from completing, it does not silently skip the client.

### 3c. Per-zone, via the identity-zone client API

In a multi-tenant deployment, `/identity-zones/{id}/clients` accepts the same properties for a
client scoped to one zone. The one difference: a client with a non-blank `tls-client-auth-ca` may
omit `client_secret` there too, but if one *is* supplied it is still checked against that zone's
secret policy. See [UAA-Client-Authentication.md](UAA-Client-Authentication.md#registering-a-tls_client_auth-client)
for the full per-path comparison.

## Step 4 — Request a token

The client authenticates with its certificate at the TLS layer — there is no `client_secret` or
Basic header, only the usual `client_id` form parameter so UAA knows which client's configuration
to check the certificate against:

```bash
curl -s -X POST "$UAA/oauth/mtls/token" \
  --cert client-cert.pem --key client-key.pem --cacert "$UAA_CACERT" \
  -d grant_type=client_credentials \
  -d client_id=mtls-demo-client \
  -d token_format=jwt \
  | tee token.json | jq .
```

`--cacert "$UAA_CACERT"` here is curl trusting *UAA's* server certificate, which is unrelated to the
CA UAA is configured to trust for the client — swap in whatever CA actually issued UAA's TLS
certificate. `--cert`/`--key` is what presents the client certificate during the handshake.

Only `client_credentials` is accepted here (the mTLS endpoint is specifically for workload
authentication, not user grants), and no refresh token is returned.

## Step 5 — Decode and verify the token

The JWT payload is base64**url**-encoded with no padding (RFC 7515) — plain `base64 -d` on its own
mishandles both the `-`/`_` alphabet and the missing padding, and on some platforms (macOS's
`/usr/bin/base64` among them) silently truncates the output instead of erroring, which is worse
than a clean failure. This helper normalizes and pads first:

```bash
decode_jwt_payload() {
  local payload
  payload=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
  case $(( ${#payload} % 4 )) in
    2) payload="${payload}==" ;;
    3) payload="${payload}=" ;;
  esac
  printf '%s' "$payload" | base64 -d
}

ACCESS_TOKEN=$(jq -r .access_token token.json)
decode_jwt_payload "$ACCESS_TOKEN" | jq .
```

Expect to see, alongside the usual claims:

```json
{
  "cnf": { "x5t#S256": "<base64url SHA-256 thumbprint of client-cert.pem>" },
  "client_auth_method": "tls_client_auth",
  "client_id": "mtls-demo-client",
  "scope": ["uaa.resource"]
}
```

`scope` here reflects the client's `authorities` (what a `client_credentials` grant may request),
not the `scope` field set at registration — the latter is relevant only when *this* client is the
audience of someone else's token, as in Step 6.

`cnf.x5t#S256` is the [RFC 8705 §3](https://www.rfc-editor.org/rfc/rfc8705#section-3) confirmation
claim: proof that the token is bound to this specific certificate. Verify it matches the
certificate you presented:

```bash
openssl x509 -in client-cert.pem -outform DER | openssl dgst -sha256 -binary \
  | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

**UAA does not enforce this binding on anyone's behalf.** It stamps `cnf`; a resource server that
wants the binding to mean something has to compute this same thumbprint from whatever certificate
*it* sees on its own connection, for every request, and reject the token if the two don't match.
Without that check, `cnf` is just an unused claim and the token behaves as an ordinary bearer token.

## Step 6 — When the resource server can't see the certificate: ask UAA

A resource server that only receives the bearer token — not the TLS connection itself — can recover
`cnf` via introspection instead. This requires a *separate* client with the `uaa.resource`
authority (unrelated to the mTLS client whose token is being inspected) — register one once:

```bash
curl -s --cacert "$UAA_CACERT" -X POST "$UAA/oauth/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
        "client_id": "resource-server-client",
        "client_secret": "resource-server-secret",
        "authorized_grant_types": ["client_credentials"],
        "scope": ["uaa.none"],
        "authorities": ["uaa.resource"]
      }'
```

Then introspect:

```bash
RESOURCE_TOKEN=$(curl -s --cacert "$UAA_CACERT" "$UAA/oauth/token" \
  -u resource-server-client:resource-server-secret \
  -d grant_type=client_credentials -d scope=uaa.resource \
  | jq -r .access_token)

curl -s --cacert "$UAA_CACERT" -X POST "$UAA/introspect" \
  -H "Authorization: Bearer $RESOURCE_TOKEN" \
  -d "token=$ACCESS_TOKEN" | jq .
```

```json
{
  "active": true,
  "client_id": "mtls-demo-client",
  "cnf": { "x5t#S256": "<same thumbprint as above>" }
}
```

The legacy `POST /check_token` endpoint returns the same `cnf` claim, for both JWT- and
opaque-format tokens. Either way, the resource server still has to do the thumbprint comparison
itself — introspection only gets the claim to a place that can see it.

## Step 7 — Check what UAA advertises

```bash
curl -s --cacert "$UAA_CACERT" "$UAA/.well-known/openid-configuration" | jq '{
  tls_client_certificate_bound_access_tokens,
  mtls_endpoint_aliases
}'
```

```json
{
  "tls_client_certificate_bound_access_tokens": true,
  "mtls_endpoint_aliases": {
    "token_endpoint": "https://localhost:8443/uaa/oauth/mtls/token"
  }
}
```

`tls_client_certificate_bound_access_tokens` is always present (`false` when `uaa.mtls-enabled` is
off); `mtls_endpoint_aliases` only appears when the feature is on.

## Step 8 — Requesting a specific audience (RFC 8707)

By default the token's `aud` is the client's own default audience. A client can be permitted to
request one of several specific audiences instead, via a curated allow-list — never an arbitrary
one it names itself:

There is no `PATCH` on `/oauth/clients/{id}` — only `GET`/`PUT`/`DELETE`. A `PUT` only needs
`client_id` plus whatever you're changing: fields you omit (the CA, the subject binding, and so on)
are preserved, not cleared.

```bash
curl -s --cacert "$UAA_CACERT" -X PUT "$UAA/oauth/clients/mtls-demo-client" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "client_id": "mtls-demo-client",
        "tls-client-auth-allowed-resources": [
          "https://billing.apps.internal",
          "https://reporting.apps.internal"
        ]
      }'
```

Then request one of them by name:

```bash
curl -s -X POST "$UAA/oauth/mtls/token" \
  --cert client-cert.pem --key client-key.pem --cacert "$UAA_CACERT" \
  -d grant_type=client_credentials \
  -d client_id=mtls-demo-client \
  -d token_format=jwt \
  -d resource=https://billing.apps.internal \
  | jq -r .access_token | { read -r t; decode_jwt_payload "$t"; } | jq .aud
# ["https://billing.apps.internal"]
```

`aud` is a JSON array here even though only one resource was requested — RFC 7519 §4.1.3 permits
collapsing a single-value `aud` to a bare string, but this code path doesn't take that option, so
don't assert an exact scalar match against it.

An absent allow-list authorizes nothing — it does not silently fall back to an unrestricted `aud`.
This is mutually exclusive with `tls-client-auth-aud-templates` (Step 9): pick one mechanism per
client.

Requesting a value that isn't on the list fails closed, without saying which value was tried:

```bash
curl -s -X POST "$UAA/oauth/mtls/token" \
  --cert client-cert.pem --key client-key.pem --cacert "$UAA_CACERT" \
  -d grant_type=client_credentials -d client_id=mtls-demo-client \
  -d resource=https://not-on-the-list.internal
```

```json
{"error":"invalid_target","error_description":"client_id=mtls-demo-client is not authorized to request the given resource"}
```

## Step 9 — Deriving claims from the certificate, and scoping to one org/space/app

`tls-client-auth-claim-mappings` pulls fields out of the certificate's subject into the issued
token's claims. This is runnable against the demo certificate from Step 2, which has only a `CN`:

```bash
curl -s --cacert "$UAA_CACERT" -X PUT "$UAA/oauth/clients/mtls-demo-client" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "client_id": "mtls-demo-client",
        "tls-client-auth-claim-mappings": [
          {"field": "subject_cn", "claim": "instance_guid"}
        ],
        "tls-client-auth-required-claims": {
          "instance_guid": "mtls-demo-client"
        }
      }'
```

Request a token (Step 4) and decode it (Step 5): the claims now include
`"instance_guid": "mtls-demo-client"`. Because the CA is shared across every app, binding on the
subject alone (Step 2/3) only proves *some* certificate it issued was presented —
`tls-client-auth-required-claims` narrows that further by checking a mapped claim's exact value.
It is an addition to the RFC 8705 subject binding, never a substitute for it.

This is also the shape Cloud Foundry itself uses, at a larger scale: Diego's instance-identity CA
signs a certificate for every app instance in the foundation, with the org/space/app GUIDs carried
as repeated `OU` attributes rather than a single `CN`. **The certificate from Step 2 has no `OU` at
all, so the example below will not match it** — it's shown for reference, not to run as-is:

```json
{
  "tls-client-auth-claim-mappings": [
    {"field": "subject_cn", "claim": "cf_instance_guid"},
    {"field": "subject_ou", "pattern": "app:(.+)", "claim": "app_guid"},
    {"field": "subject_ou", "pattern": "space:(.+)", "claim": "space_guid"},
    {"field": "subject_ou", "pattern": "organization:(.+)", "claim": "org_guid"}
  ],
  "tls-client-auth-required-claims": { "space_guid": "11111111-2222-3333-4444-555555555555" }
}
```

See
["Scoping a client to a specific org/space/app"](UAA-Client-Authentication.md#scoping-a-client-to-a-specific-orgspaceapp)
for the full worked example, including `tls-client-auth-sub-template` for deriving a custom `sub`.

## Rotating the CA without downtime

`tls-client-auth-ca` (and `tls-client-auth-trusted-proxy-ca`) accept multiple **concatenated** PEM
certificates — every one of them becomes an independent trust anchor. `ca-cert.pem` from Step 2 is
the outgoing CA here; generate an incoming one the same way:

```bash
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout new-ca-key.pem -out new-ca-cert.pem -subj "/CN=Demo mTLS CA v2"

cat ca-cert.pem new-ca-cert.pem > ca-bundle.pem

curl -s --cacert "$UAA_CACERT" -X PUT "$UAA/oauth/clients/mtls-demo-client" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"mtls-demo-client\", \"tls-client-auth-ca\": $(jq -Rs . < ca-bundle.pem)}"
```

Certificates issued by either CA now authenticate. Once every certificate issued by the old CA has
expired or been reissued under the new one, submit `tls-client-auth-ca` with just the new CA alone.
A malformed entry in the bundle rejects the whole value at update time — it never silently trusts a
subset of it.

## Behind a proxy: the `X-Forwarded-Client-Cert` topology

In a real Cloud Foundry deployment, the app's certificate goes to the Gorouter, not straight to
UAA — the Gorouter terminates that connection, and forwards the client's certificate to UAA in the
`X-Forwarded-Client-Cert` header over its own, separate backend mTLS connection. Simulating this
locally needs **two** certificate pairs: the original client's (as above), and a second CA/cert
pair standing in for the Gorouter's own backend identity.

```bash
# A second CA, standing in for the one that signs the Gorouter's backend certificate.
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout proxy-ca-key.pem -out proxy-ca-cert.pem -subj "/CN=Demo Backend Proxy CA"
openssl req -newkey rsa:2048 -nodes -keyout proxy-key.pem -out proxy.csr \
  -subj "/CN=demo-gorouter-backend"
openssl x509 -req -in proxy.csr -CA proxy-ca-cert.pem -CAkey proxy-ca-key.pem -CAcreateserial \
  -days 90 -out proxy-cert.pem
```

Register `tls-client-auth-trusted-proxy-ca` on the client — this switches it to proxy-only; a
direct connection without the header is refused even if its own certificate would otherwise
validate:

```bash
curl -s --cacert "$UAA_CACERT" -X PUT "$UAA/oauth/clients/mtls-demo-client" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"mtls-demo-client\", \"tls-client-auth-trusted-proxy-ca\": $(jq -Rs . < proxy-ca-cert.pem)}"
```

The request now presents the *proxy's* certificate at the TLS layer, and the *original client's*
certificate base64-encoded (standard base64, raw DER, no PEM markers) in the header — exactly the
encoding the Gorouter itself produces with `forwarded_client_cert: sanitize_set`:

```bash
XFCC=$(openssl x509 -in client-cert.pem -outform DER | base64 | tr -d '\n')

curl -s -X POST "$UAA/oauth/mtls/token" \
  --cert proxy-cert.pem --key proxy-key.pem --cacert "$UAA_CACERT" \
  -H "X-Forwarded-Client-Cert: $XFCC" \
  -d grant_type=client_credentials -d client_id=mtls-demo-client | jq .
```

Both checks run: the genuine TLS peer (the `curl` process here, standing in for the Gorouter) must
validate against `tls-client-auth-trusted-proxy-ca`, *and* the header-derived certificate must
satisfy the client's ordinary `tls-client-auth-ca` / subject-binding configuration, exactly as in
Step 4. An operator who needs both a proxied and a direct-connection path for what is conceptually
"the same" workload registers **two separate clients** — this is a per-client, mutually exclusive
setting, not two ways of satisfying one requirement. See
["Deployment topology"](UAA-Client-Authentication.md#deployment-topology) for the full reasoning.

## Troubleshooting

Every error below is a `401`/`400` with no OAuth error body unless shown, and none echo back
whatever value was rejected — a caller cannot use the error message to probe what it got wrong.

| You did this | You get | Why | Fix |
|---|---|---|---|
| Requested `/oauth/mtls/token` with `uaa.mtls-enabled` unset | `404` | The endpoint does not exist at all with the feature off | Set `uaa.mtls-enabled: true` and restart |
| `GET /oauth/mtls/token` | `405`, `Allow: POST` | The endpoint is POST-only | Use `POST` |
| Registered a client with `tls-client-auth-ca` but no subject parameter | `400 invalid_client`, registration refused | RFC 8705 §2.1.2 requires exactly one of the five subject parameters | Add exactly one of `tls_client_auth_subject_dn`/`_san_dns`/`_san_uri`/`_san_ip`/`_san_email` |
| Presented no certificate at all | `401 invalid_client`: `tls_client_auth: certificate validation failed` | — | Check `--cert`/`--key` are set (direct), or the proxy's XFCC header (proxied) |
| Certificate doesn't chain to `tls-client-auth-ca`, or is expired | `401 invalid_client`: `tls_client_auth: certificate chain validation failed: <reason>` | — | Re-check which CA signed the certificate, and its validity window |
| Certificate chains to the CA but has the wrong subject | same message as above | The subject binding deliberately produces the same denial as a wrong-CA certificate, so a caller cannot distinguish "wrong CA" from "right CA, wrong client" | Confirm `$SUBJECT_DN` (or whichever SAN) matches *exactly*, via `openssl x509 -noout -subject -nameopt RFC2253` |
| `tls-client-auth-required-claims` entry doesn't match | same message as above | Same deliberate non-disclosure | Re-derive the claim values via `tls-client-auth-claim-mappings` and compare by hand |
| Sent a `client_secret` or Basic auth for a client that has `tls-client-auth-ca` | `401 invalid_client`: `tls_client_auth: configured clients must authenticate at /oauth/mtls/token without client credentials` | A certificate-bound client cannot also obtain unbound tokens | Drop the secret; authenticate with the certificate only |
| Requested any grant other than `client_credentials` | `400 invalid_grant`: `the mTLS token endpoint only issues client_credentials tokens` | This endpoint exists for workload identity, not user grants | Use `client_credentials` |
| `resource=` not on the client's `tls-client-auth-allowed-resources`, or the client has no list | `400 invalid_target`: `client_id=<id> is not authorized to request the given resource` | An absent allow-list authorizes nothing | Add the value to the list (Step 8), or omit `resource` entirely |
| `tls-client-auth-allowed-resources` and `tls-client-auth-aud-templates` both set | `400 invalid_client`, registration refused: `...are mutually exclusive for client_id=...` | Two mechanisms for setting `aud` on one client | Pick one |
| A `tls-client-auth-claim-mappings` `pattern` targets `subject_cn`/`subject_o` | `400 invalid_client`, registration refused | `pattern` only applies to `subject_ou` | Drop `pattern` for `subject_cn`/`subject_o`, or move the mapping to `subject_ou` |
| `PATCH /oauth/clients/{id}` | `405` (or an unrelated-looking `403`/CSRF error, depending on what else is mapped at that path) | The client-admin API has no `PATCH` | Use `PUT` with at least `client_id`; omitted fields are preserved |
| `curl: (60) SSL certificate problem` on *every* request, including plain `/oauth/token` | — | `--cacert` is pointing at the demo mTLS CA from Step 2 instead of whatever CA signed UAA's own HTTPS certificate | Set `$UAA_CACERT` correctly — see Prerequisites; the two files are unrelated |
| `uaa.mtls-enabled: true` is set, but every request still gets "no certificate presented" | `401 invalid_client: certificate validation failed`, with nothing relevant in the logs | UAA is only serving plain HTTP on that port — there is no TLS handshake for a certificate to be exchanged on | Confirm the port is actually HTTPS (`curl -v` shows a TLS handshake), not just that the flag is set |

For the complete error table (including the configuration-error and malformed-CA cases) see
[UAA-Client-Authentication.md](UAA-Client-Authentication.md#error-responses-at-oauthmtlstoken).

## Full end-to-end script

Everything above, concatenated into one runnable script that also starts and stops its own UAA:
boots `scripts/boot/boot-with-tls.sh` in the background (which builds the WAR and generates the
TLS keystore on a first run, if either is missing), waits for it to come up, runs through Steps
2-5, then shuts it down on the way out -- success or failure, via the `trap`.

Run from the repository root; it is the only prerequisite.

```bash
#!/usr/bin/env bash
set -euo pipefail

UAA="${UAA:-https://localhost:8443/uaa}"
# Resolved to an absolute path before cd'ing below -- a relative default would stop
# resolving the moment this script changes into $WORKDIR.
UAA_CACERT="${UAA_CACERT:-$(pwd)/scripts/certificates/CA.crt}"

BOOT_LOG=$(mktemp)
./scripts/boot/boot-with-tls.sh > "$BOOT_LOG" 2>&1 &
BOOT_PID=$!
# $BOOT_PID is UAA's own java process, not a wrapper -- boot-with-tls.sh execs it, replacing
# itself, so this is the right PID to stop at the end no matter how long the server took to start.
trap 'kill "$BOOT_PID" 2>/dev/null || true' EXIT

echo "waiting for UAA to come up (first run also builds the WAR and generates certificates,"
echo "which can take a couple of minutes)..."
for _ in $(seq 1 120); do
  if curl -sf --cacert "$UAA_CACERT" -o /dev/null "$UAA/.well-known/openid-configuration" 2>/dev/null; then
    echo "UAA is up"
    break
  fi
  if ! kill -0 "$BOOT_PID" 2>/dev/null; then
    echo "boot-with-tls.sh exited before UAA came up -- see $BOOT_LOG" >&2
    cat "$BOOT_LOG" >&2
    exit 1
  fi
  sleep 2
done

WORKDIR=$(mktemp -d); cd "$WORKDIR"

decode_jwt_payload() {
  local payload
  payload=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
  case $(( ${#payload} % 4 )) in
    2) payload="${payload}==" ;;
    3) payload="${payload}=" ;;
  esac
  printf '%s' "$payload" | base64 -d
}

# Certificates
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout ca-key.pem -out ca-cert.pem -subj "/CN=Demo mTLS CA"
openssl req -newkey rsa:2048 -nodes -keyout client-key.pem -out client.csr \
  -subj "/CN=mtls-demo-client"
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -days 90 -out client-cert.pem
SUBJECT_DN=$(openssl x509 -in client-cert.pem -noout -subject -nameopt RFC2253 | sed 's/^subject=//')

# Register the client
ADMIN_TOKEN=$(curl -sf --cacert "$UAA_CACERT" "$UAA/oauth/token" -u admin:adminsecret \
  -d grant_type=client_credentials -d scope=clients.write | jq -r .access_token)

cat > client.json <<JSON
{
  "client_id": "mtls-demo-client",
  "authorized_grant_types": ["client_credentials"],
  "scope": ["uaa.none"],
  "authorities": ["uaa.resource"],
  "tls-client-auth-ca": $(jq -Rs . < ca-cert.pem),
  "tls_client_auth_subject_dn": "$SUBJECT_DN"
}
JSON
curl -sf --cacert "$UAA_CACERT" -X POST "$UAA/oauth/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d @client.json > /dev/null
echo "client registered"

# Get a certificate-bound token
curl -sf -X POST "$UAA/oauth/mtls/token" \
  --cert client-cert.pem --key client-key.pem --cacert "$UAA_CACERT" \
  -d grant_type=client_credentials -d client_id=mtls-demo-client -d token_format=jwt \
  > token.json
ACCESS_TOKEN=$(jq -r .access_token token.json)
echo "token issued"

# Verify the confirmation claim matches the certificate
TOKEN_THUMBPRINT=$(decode_jwt_payload "$ACCESS_TOKEN" | jq -r '.cnf["x5t#S256"]')
CERT_THUMBPRINT=$(openssl x509 -in client-cert.pem -outform DER | openssl dgst -sha256 -binary \
  | openssl base64 -A | tr '+/' '-_' | tr -d '=')
if [ "$TOKEN_THUMBPRINT" = "$CERT_THUMBPRINT" ]; then
  echo "cnf.x5t#S256 matches the certificate"
else
  echo "MISMATCH: $TOKEN_THUMBPRINT != $CERT_THUMBPRINT" >&2
  exit 1
fi

echo "done -- stopping UAA"
# The trap above stops $BOOT_PID as this script exits; nothing further to do here.
```

## Further reading

* [UAA-Client-Authentication.md](UAA-Client-Authentication.md) — full property reference, every
  error response, deployment topology, compatibility notes
* [UAA-Configuration-Reference.md](UAA-Configuration-Reference.md#uaamtls-enabled) — the
  `uaa.mtls-enabled` property
* [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) — OAuth 2.0 Mutual-TLS Client Authentication
* [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) — Resource Indicators for OAuth 2.0
* [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514) / [RFC 4517](https://www.rfc-editor.org/rfc/rfc4517) —
  distinguished-name string form and comparison rules used for `tls_client_auth_subject_dn`
