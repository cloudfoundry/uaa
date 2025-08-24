# Registering Okta as external, public OIDC provider in UAA

Okta can be setup as an [OIDC provider](https://developer.okta.com/docs/guides/add-an-external-idp/openidconnect/configure-idp-in-okta/) for UAA login.
To prevent storing a client secret in UAA configuration and all of its successor problems like secret rotation and so on, register the
external OIDC provider with a public client.

1. Create an OIDC application and set it with [PKCE public](https://developer.okta.com/blog/2019/08/22/okta-authjs-pkce#use-pkce-to-make-your-apps-more-secure).
   Register the "Redirect URIs" in the application section "OpenID Connect Configuration"

   Add the following URI in list field:
   `http://{UAA_HOST}/login/callback/{origin}`. [Additional documentation for achieving this can be found here](https://developer.okta.com/docs/guides/implement-auth-code-pkce/overview/).
   
2. Copy client id.

3. Minimal OIDC configuration needs to be added in login.ym.
   Read configuration refers to 'https://<your-tenant>.okta.com/.well-known/openid-configuration' for discoveryUrl and issuer

        login:
          oauth:
            providers:
              okta.public:
                type: oidc1.0
                discoveryUrl: https://trailaccount.okta.com/.well-known/openid-configuration
                issuer: https://trailaccount.okta.com
                scopes:
                  - openid
                linkText: Login with Okta-Public
                showLinkText: true
                relyingPartyId: 0iak4aiaC4HV39L6g123

4. Ensure that the scope `openid` is included in the`scopes` property.

5. Restart UAA. You will see `Login with Okta-Public` link on your login page.
