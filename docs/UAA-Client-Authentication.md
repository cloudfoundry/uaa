# UAA Client Authentication

UAA acts as an OAuth2 / OIDC server, and this requires the separate authentication of users and clients. This document focuses on
the clients and in detail on the key-based client authentication because this has special behaviors.
In [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) the password of a client is specified as so-called secret (parameter client_secret). Its possession
or better the process of checking its possession means the authentication process.

The secrets can be passed to a server in different ways. It can happen through the HTTP header and/or the body. In the case that an Authorization header is used,
the encoding of the secret needs to be done according to the RFC 6749. UAA fixed this behavior with <https://github.com/cloudfoundry/uaa/issues/778>.
The OIDC standard defines additional authentication mechanisms, see [section 9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication).
The usage of secrets via client_secret_basic and client_secret_post is straightforward to set up and to use, however, if system-to-system communication is
in use, this can be a security problem because it will be hard to change secrets in running systems. The use of many secrets is not
supported, also because the check can only be done sequentially. The exchange of a secret is a security problem in itself. Therefore, the newer
standards define token-based authentication mechanisms for OAuth2 clients. They are:

* private_key_jwt [OIDC core standard](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) and [RFC 7523 from OAuth2 standard](https://www.rfc-editor.org/info/rfc7523)
* tls_client_auth [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)

## New methods

The new methods are based on asymmetric trust relation, so that the keys are divided into a private and a public one. The private key should never leave
the original system, but only the public key should be exchanged.

### private_key_jwt (Partly finished)

The standard private_key_jwt is similar to the existing JWT bearer flow, but JWT bearer is for user principle propagation, whereas private_key_jwt
is used for client authentication only. The used technics are similar and therefore the trust model is similar. Both usages are specified in the same
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.txt). The JWT bearer trust is based on parameters tokenKey and/or tokenKeyUrl parameter, part of the
identity providers configuration section. The signature check of a client jwt can be verified with a set
of public keys, and this set can contain many keys because each key has its own kid (key id). The keys can be stored in UAA's own persistency or with
a dynamic token key URI. OIDC has defined the parameter jwks_uri for this already. The structure of the keys is defined with [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
UAA provides its own jwks_uri with endpoint /token_keys. The content of this endpoint is [JWKS](https://datatracker.ietf.org/doc/html/rfc7517#section-5).

The content of the JWT (parameter client_assertion) can be different. The standards define the difference. The [OIDC core standard](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
 simplifies the structure so that issuer and subject are the client_id of the authenticated OAuth2 client. The key rotation is supported with
jwks_uri, which retrieves the JWK. You can only have one JWKS_URI by the client. For the [RFC 7523 from OAuth2 standard](https://www.rfc-editor.org/info/rfc7523) the
structure is more complex, but with seperated issuer and subject there can be more than one entry of federated credential.

The new parameters for JWKS Trust in UAA clients are:

* jwks_uri
* jwks

This should allow continuous trust between UAA to UAA communication, e.g., using own UAA instances or within a UAA using different zones.

The new parameter for federated Credentials in UAA clients is (Work in progress parameter):

* jwt_creds

### tls_client_auth ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705))

Mutual-TLS client authentication: a client presents an X.509 certificate at the TLS layer
instead of a `client_secret` or a signed JWT assertion. UAA validates the certificate against
a per-client trusted CA and, optionally, derives JWT claims from the certificate's subject
fields (e.g. mapping a Cloud Foundry app instance identity certificate to `app_guid`/
`space_guid`/`org_guid` claims).

The client is authenticated on the fixed dedicated endpoint, `/oauth/mtls/token`, rather than
the regular `/oauth/token`. A nonblank `tls-client-auth-ca` is the sole inbound mTLS selector
for a client. This dedicated endpoint routing is what's scoped: only requests to
`/oauth/mtls/token` attempt to authenticate the caller via a presented client certificate --
requests to `/oauth/token` are never affected by this.

The underlying TLS-layer change, however, is **connector-wide, not per-endpoint**: enabling
this feature (`uaa.mtls-enabled`) reconfigures the whole embedded Tomcat connector to request a
client certificate on *every* TLS handshake to this UAA instance (`certificateVerification=
optionalNoCA`; see `MtlsClientAuthTomcatCustomizer`), regardless of which path the request is
ultimately routed to. Any TLS client connecting to any UAA endpoint will therefore be prompted
for a certificate during the handshake -- well-behaved clients (including Go's `crypto/tls`)
simply respond with an empty `Certificate` message if they have no certificate matching the
connector's advertised acceptable-issuer list, so this doesn't outright break other endpoints,
but it is a deployment-wide TLS-layer change, not one isolated to `/oauth/mtls/token`.

#### Deployment topology

UAA itself only ever sees the certificate presented by its *immediate* TLS peer -- whatever
that happens to be depends on how UAA is deployed:

* **Behind a Gorouter** with `forwarded_client_cert: sanitize_set` (the typical Cloud
  Foundry deployment): the Gorouter terminates the client's TLS connection, validates it, and
  forwards the client's certificate to UAA in the `X-Forwarded-Client-Cert` header over its own
  backend mTLS connection. Here, UAA's immediate TLS peer is the Gorouter itself, not the
  original client.
* **Direct connections**, e.g. an app connecting straight to UAA over BOSH DNS
  (`uaa.service.cf.internal`) where Application Security Groups permit it, bypassing the
  Gorouter entirely: UAA's immediate TLS peer *is* the original client.

`tls-client-auth-trusted-proxy-ca` determines which of the two topologies a *given client* uses --
the two are mutually exclusive per client, not two ways of satisfying the same requirement:

* **Not configured:** the client is direct-connection-only. UAA always authenticates it using the
  certificate its immediate TLS peer actually presented during the handshake, and never consults
  the `X-Forwarded-Client-Cert` header at all (even if one happens to be present -- e.g. noise
  from an unrelated proxy in the network path).
* **Configured:** the client is proxy-only. UAA requires the `X-Forwarded-Client-Cert` header to
  actually be present, and the genuine TLS peer that presented it to validate against this CA,
  before trusting the header-derived certificate. A direct connection (no header) is always
  rejected for this client, even if its own certificate happens to validate against the configured
  CA.

An operator who needs both a Gorouter-fronted access pattern and a direct-connection access
pattern for what is conceptually "the same" workload registers **two separate UAA clients** -- one
with `tls-client-auth-trusted-proxy-ca` set (proxy path) and one without it (direct path) -- rather
than expecting one client to accept either.

#### Scoping a client to a specific org/space/app

Because Cloud Foundry's Diego instance-identity CA is shared across every app instance in a
foundation, any two clients configured with the same `tls-client-auth-ca` can otherwise
authenticate each other's certificates -- PKIX chain validation alone only proves a certificate
was issued by the configured CA, not that it belongs to *this* client specifically. Configure
`tls-client-auth-required-claims` to close this gap for a client that should only be reachable by
a specific subset of apps:

```yaml
tls-client-auth-claim-mappings:
  - field: subject_ou
    pattern: "space:(.+)"
    claim: space_guid
tls-client-auth-required-claims:
  space_guid: <specific-space-guid>
```

An operator who needs both a broadly-scoped client (e.g. the generic `instance-identity` client,
accepting any app in the foundation) and a narrowly-scoped one (e.g. limited to a single space)
registers them as two separate UAA clients, only the latter configuring
`tls-client-auth-required-claims`.

#### Configuration

Per-client properties (set via the client-admin API, `oauth.clients` bootstrap, or the client
admin UI, alongside the client's other properties such as `authorized-grant-types`):

The mTLS token endpoint is fixed at `/oauth/mtls/token`; it is not configurable. A client opts
into mTLS by configuring a nonblank `tls-client-auth-ca`. The client must use that endpoint and
present a certificate whose chain validates to the configured CA; no separate
`token-endpoint-auth-method` property is used or supported.

| Property | Required | Description |
|----------|----------|--------------|
| `tls-client-auth-ca` | yes | PEM-encoded CA certificate. This is the per-client mTLS selector: requests to the fixed `/oauth/mtls/token` endpoint authenticate with a presented leaf certificate only when it chains to this CA. |
| `tls-client-auth-trusted-proxy-ca` | conditional | PEM-encoded CA certificate the Gorouter's own backend mTLS certificate must chain to. Configuring this switches the client to the Gorouter/XFCC-forwarding-only topology (requiring the `X-Forwarded-Client-Cert` header) -- see "Deployment topology" above. Leave unset for a direct-connection-only client. |
| `tls-client-auth-required-claims` | no | Map of `claimName -> requiredValue`, checked against the values already produced by `tls-client-auth-claim-mappings`. When configured, authentication fails unless every entry matches exactly -- e.g. `{space_guid: "<specific-space-guid>"}` scopes this client to a single CF space, even if other clients share the same `tls-client-auth-ca`. |
| `tls-client-auth-claim-mappings` | no | List of `{field, pattern, claim}` mappings from certificate subject fields (`subject_cn`, `subject_ou`, `subject_o`) to JWT claim names. `subject_cn` and `subject_o` map their values directly; `pattern` is supported only for `subject_ou`, where it extracts a capture group. Patterns are UAA administrator-controlled configuration and are evaluated on every mTLS authentication request; use efficient Java regular expressions and avoid patterns with catastrophic backtracking. |
| `tls-client-auth-sub-template` | no | Template string rendered (using the mapped claim values) to produce the JWT `sub` claim. |
| `tls-client-auth-aud-templates` | no | List of template strings rendered to produce the JWT `aud` claim. |

Example (Gorouter-fronted; a Cloud Foundry app instance identity certificate mapped to
`cf_instance_guid`/`app_guid`/`space_guid`/`org_guid` claims):

```yaml
tls-client-auth-ca: <instance-identity CA certificate PEM>
tls-client-auth-trusted-proxy-ca: <Gorouter backend mTLS CA certificate PEM, e.g. service_cf_internal_ca>
tls-client-auth-claim-mappings:
  - field: subject_cn
    claim: cf_instance_guid
  - field: subject_ou
    pattern: "app:(.+)"
    claim: app_guid
  - field: subject_ou
    pattern: "space:(.+)"
    claim: space_guid
  - field: subject_ou
    pattern: "organization:(.+)"
    claim: org_guid
```

For the direct-connection topology described above, omit `tls-client-auth-trusted-proxy-ca`
entirely rather than setting it -- configuring it at all switches this client to proxy-only.

## Configs

Here is a brief example of the `clients` section:

```yaml
oauth:
  clients:
    uaa-trust-uri:
      authorities: scim.zones,uaa.zones.read,uaa.zones.write,uaa.admin,clients.read,clients.write,clients.secret,zones.read,zones.uaa.admin
      authorized-grant-types: client_credentials
      id: uaa_trust
      scope: none
      jwks_uri: http://localhost:8080/uaa/token_keys
    uaa-trust-keys:
      authorities: scim.zones,uaa.zones.read,uaa.zones.write,uaa.admin,clients.read,clients.write,clients.secret,zones.read,zones.uaa.admin
      authorized-grant-types: client_credentials
      id: uaa_trust
      scope: none
      jwks: |
        {
          "keys": [
            {
              "kty": "RSA",
              "e": "AQAB",
              "use": "sig",
              "kid": "legacy-token-key",
              "alg": "RS256",
              "n": "qMClJXznycV2bQ1pFbN8W-AWSYhpS2MVAGhkWNlmxv2Ix0_-n6zjivjdoxcq7RJR4kVycoVeD07DiWElYSnQLdeQPgKAcBiwilR30UyyDTKcqDQQ5rkCg2ONlwV0aMsg74KaXeXsV653ASs3FYEtuS1aD_Db5-FyXF8HkHo8xy19NUnqsDWQnh1Hhklynxu2tvW0fw2oDE1pwNl-WLEVPtlcpCtf4VSv-GawtBiI6xmYsGBMC9w29ESHFqPw0NSCRhlyJf6rDBNH_766mzK_vEzA4rzGTBEUqDxTg_8JpRhh9D3qljSsmqCtpQoloOAaUKCqSJb_hKPspe-7r9cYmw"
            }
          ]
        }
```

The example configuration above with jwks_uri enables continuous trust to a running UAA.

Here is a brief example of the oauth providers section, where UAA is acting as a client.

```yaml
login:
  oauth:
    providers:
      uaa.proxy:
        type: oidc1.0
        passwordGrantEnabled: true
        discoveryUrl: http://localhost:8080/uaa/oauth/token/.well-known/openid-configuration
        issuer: http://localhost:8080/uaa/oauth/token
        linkText: Login with another UAA
        relyingPartyId: uaa-trust-uri
        jwtClientAuthentication: true
        showLinkText: true
```

The option jwtClientAuthentication creates during the proxy flow a client assertion which is based on OIDC private_key_jwt.

### Developer implementation

As a developer, you should use the [UAA documentation](https://docs.cloudfoundry.org/api/uaa/version/77.18.0/index.html#token). There is a description
about the new parameters client_assertion and client_assertion_type. In addition, you can check in the retrieved access_token tokens for the existence
of claim client_auth_method with value private_key_jwt, (client_auth_method=private_key). This claim should guarantee the used method of client
authentication. Tokens without this claim are authenticated with secrets. There might be use-cases where a stronger authentication mechanism is
required.

### Production use

The support of private_key_jwt (according to OIDC) for a production system is given with the end of Q4/2024.
