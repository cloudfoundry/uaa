# Registering SAP IAS as external, public OIDC provider in UAA

SAP IAS can be setup as an [OIDC provider](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/Cloud/en-US/a789c9c8c0f5439da8c30b5d9e43bece.htm) for UAA login.
To prevent storing a client secret in UAA configuration and all of its successor problems like secret rotation and so on, register the
external OIDC provider with a public client.

1. Create an OIDC application and set it with [type public](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/Cloud/en-US/a721157cd40544eb9bad40085cf8ec15.html)
   * in Trust / OpenID Configuration / Grant Types / Authorization Code Flow / Enforce PKCE (S256)
3. Register the "Redirect URIs" in the application section "OpenID Connect Configuration"
   * Add the following URI in list field:
   `https://{UAA_HOST}/login/callback/{origin}`. [Additional documentation for achieving this can be found here](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/Cloud/en-US/1ae324ee3b2d4a728650eb022d5fd910.html).
   * E.g., for a UAA part of a CF-Deployment, this is `https://login.cf.<domain>/login/callback/{origin}`
   * `{origin}` - is the id you of the OIDC provider you will use in UAA in the next step
   
2. Go to the "Client Authentication" section and check "Allow Public Client Flows".
   * This will generate the "client id" on the top of the page
   * Copy "client id", to use for the uaa configuration.

4. Minimal OIDC configuration needs to be added in `uaa.yml` or `login.yml` (depending on the setup).
   Read configuration refers to '[https://<tenant ID>.accounts.ondemand.com/.well-known/openid-configuration](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/Cloud/en-US/c297516bae4547eb82eeed80fea2b937.html)' for discoveryUrl and issuer. E.g., in the example below `ias.public` was selected as `{origin}`

        login:
          oauth:
            providers:
              ias.public:
                type: oidc1.0
                discoveryUrl: https://<ias_tenant_id>.accounts.ondemand.com/.well-known/openid-configuration
                issuer: https://<ias_tenant_id>.accounts.ondemand.com
                scopes:
                  - openid
                  - email
                  - profile
                linkText: Login with IAS-Public
                showLinkText: true
                relyingPartyId: <client_id>
                addShadowUserOnLogin: true

6. Ensure that the scope `openid`, `email` and `profile` is included in the `scopes` property. Then UAA shadow user (if addShadowUserOnLogin=true) is created with all properties. 

7. Restart UAA.
   * You may see `Login with IAS-Public` link on your login page.
   * Or if the link is not displayed, you need to enter the `{origin}` manually and then login against it

9. (optional) For CF Login, use `cf login --sso` and select the provider.
    * Trying to log in with User/Pass requires a confidential OAuth Client, creating a Secret in the Client Authentication tab, adding it as `relyingPartySecret` property and disabling "Enforce PKCE"
  
8. (Optional) Use e-mail for Login Id instead of P-user
   1. In the IAS Admin Page, under "Trust / Single Sign-on / Subject Name Identifier / Basic Configuration"
      * Select "Select a basic attribute" : "Email"
   2. In `uaa.yml` append the following configuration, to the `login.oauth.providers.{origin}` section (at the same level as the other properties from the example above):
      ```
      attributeMappings:
          user_name: "email"
      ```
