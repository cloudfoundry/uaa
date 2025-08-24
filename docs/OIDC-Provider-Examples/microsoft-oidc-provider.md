# Registering your Microsoft Entra (former Azure) as external OIDC provider in UAA

You can use your Microsoft account to be set up as an [OIDC provider](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) for 
UAA login. To prevent storing a client secret in UAA configuration, either register the external OIDC provider with a public client or use
X509 [certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials).
Prerequisite is the setup OIDC version 2.0. You have to know your tenant ID. Then you know your issuer using 
a link https://login.microsoftonline.com/{tenant}/v2.0/. Your discovery URL is https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration. 

1. Create a new application in your App registrations in your directory. After creation, you see in the Overview section the client_id, which is needed.
2. Configure in the Authentication section a Web Redirect URI for your UAA setup. In addition, it is recommended to add your  
UAA/logout.do as Front-channel logout URL, so that you also get SLO for your browser flows.

   Add the following URI in the redirect URL:

   `https://{UAA_HOST}/login/callback/{origin}`. [Additional documentation for achieving this can be found here](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url).

3. In the section Certificates and secrets it is recommended to store your X509. You can get it from your UAA/token_keys from property x5c.
   You can set up UAA with X509 certificates in JWT with your existing private key with the following commands:

```console
   openssl req -x509 -sha256 -new -key <your-key-from-uaa-yaml> -out <server.csr>
   openssl x509 -sha256 -days 365 -in <server.csr> -signkey <your-key-from-uaa-yaml>
 ```

4. Copy the received X509 certificate into your uaa.yml.

```yaml
        jwt:
         token:
           policy:
             activeKeyId: legacy-token-key
             keys:
               legacy-token-key:
                 signingAlg: RS256
                 signingKey: |
                   -----BEGIN PRIVATE KEY-----
                   ... <your existing private key>
                   -----END PRIVATE KEY-----
                 signingCert:
                   -----BEGIN CERTIFICATE-----
                   ... <your generated X509>
                   -----END CERTIFICATE-----
 ```

5. Minimal OIDC configuration needs to be added in login.yml. Read configuration refers to '[https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)' for discoveryUrl and issuer

```yaml
        login:
          oauth:
            providers:
              microsoft:
                type: oidc1.0
                discoveryUrl: https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
                issuer: https://login.microsoftonline.com/{tenant}/v2.0
                scopes:
                  - openid
                  - email
                  - profile
                attributeMappings:
                  user_name: email
                linkText: Login with Microsoft
                showLinkText: true
                relyingPartyId: 3feb7ecb-d106-4432-b335-aca2689ad123
                jwtclientAuthentication: true
 ```

6. Ensure that the scope `openid`, `email` and `profile` is included in the`scopes` property. Then UAA shadow user (if addShadowUserOnLogin=true) is 
created with the most important properties like first and last name and the email. The UAA username can be defined with a
custom configuration as pointed out in the example. If the user_name mapping is not set, it will be an opaque id always.
If you want to use another attribute from your directory, define the claim in the token configuration and map it here.

7. Restart UAA. You will see `Login with Microsoft` link on your login page.
