# UAA Client Authentication
UAA acts as OAuth2 / OIDC server and this requires the separation of users and clients. This document focuses on
the clients and in detail on the client authentication, because this has special behaviors.
In [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) the password of a client is specified as so called client_secret. Its possession
or better the process of checking its possession means the authentication process.

The secrets can be passed to a server in different ways. It can happen through HTTP header and/or the body. In case of header the Authorization header is used, but
the encoding of the secret needs to be done according to the RFC 6749. UAA fixed this behavior with https://github.com/cloudfoundry/uaa/issues/778.
The OIDC standard defines more authentication mechanism, see [section 9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication).
The usage of secrets via client_secret_basic and client_secret_post is easy to setup and easy to use, however if system to system communication is
in use, this can get a security problem, because it will be hard to change secrets in running systems. The use of many secrets is not
supported, also because the check can only be done sequentially. The exchange of a secret is a security problem in it self. Therefore the newer
standards define further token based authentication mechanism for OAuth2 clients. They are:

* private_key_jwt [OIDC core standard](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
* tls_client_auth [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)

## New methods
The new methods are based on asymmetric trust relation, so that the keys are divided into a private and a public one. The private key should never leave
the original system, but only the public key should be exchanged.

### private_key_jwt (Experimental Feature)
The standard private_key_jwt is similar to the existing JWT bearer flow, but JWT bearer is for user principle propagation, whereas private_key_jwt
is used for client authentication only. The used technics are similar and therefore the trust model is similar. Both usages are specified in the same
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.txt). The JWT bearer trust is based on parameters tokenKey and/or tokenKeyUrl parameter, part of the
identity providers configuration section. The signature check of a client jwt can be verified with a set
of public keys and this set can contain many keys because each key has its own kid (key id). The keys can be stored in UAA own persistency or with
a dynamic token key URI. OIDC has defined the parameter jwks_uri for this already. The structure of the keys is defined with [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
UAA provides its own jwks_uri with endpoint /token_keys. The content of this endpoint is [JWKS](https://datatracker.ietf.org/doc/html/rfc7517#section-5).

The new parameters for UAA clients are:

* jwks_uri
* jwks

This should allow a continuous trust between a UAA to UAA communication, e.g. using own UAA instances or within a UAA using different zones.

### tls_client_auth (Planned Feature)
Not yet defined a release date.

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
The example config above with jwks_uri enables continuous trust to a running uaa.

### Developer implementation
As deverloper you should use the [UAA documention](https://docs.cloudfoundry.org/api/uaa/version/76.23.0/index.html#token). There is a description
about the new parameters client_assertion and client_assertion_type. In addition, you can check in the retrieved access_token tokens for the existence 
of claim client_auth_method with value private_key_jwt, (client_auth_method=private_key). This claim should guarantee the used method of client 
authentication. Tokens without this claim are authenticated with secrets. There might be use-cases where a stronger authentication mechanism is 
required.

### Production use

The support of private_key_jwt for a production is planned with end of Q4/2023. The use for other purposes is given with a release of UAA starting  
from version 76.23.0 or higher.
