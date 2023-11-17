# Registering SAP IAS as external, public OIDC provider in UAA

SAP IAS can be setup as an [OIDC provider](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/Cloud/en-US/a789c9c8c0f5439da8c30b5d9e43bece.htm) for UAA login.
In order to prevent storing a client secret in UAA configuration and all of it's successor problems like secret rotation and so on, register the
external OIDC provider with a public client.

1. Create an OIDC application and set it with [type public](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/Cloud/en-US/a721157cd40544eb9bad40085cf8ec15.html).
   Register the "Redirect URIs" in the application section "OpenID Connect Configuration"

   Add following URI in list field:
   `http://{UAA_HOST}/login/callback/{origin}`. [Additional documentation for achieving this can be found here](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/Cloud/en-US/1ae324ee3b2d4a728650eb022d5fd910.html).
   
2. Copy client id.

3. Minimal OIDC configuration needs to be added in login.ym.
   Read configuration refer to '[https://<tenant ID>.accounts.ondemand.com/.well-known/openid-configuration](https://help.sap.com/viewer/6d6d63354d1242d185ab4830fc04feb1/Cloud/en-US/c297516bae4547eb82eeed80fea2b937.html)' for discoveryUrl and issuer

        login:
          oauth:
            providers:
              ias.public:
                type: oidc1.0
                discoveryUrl: https://trailaccount.accounts.ondemand.com/.well-known/openid-configuration
                issuer: https://trailaccount.accounts.ondemand.com
                scopes:
                  - openid
                  - email
                  - profile
                linkText: Login with IAS-Public
                showLinkText: true
                relyingPartyId: 3feb7ecb-d106-4432-b335-aca2689ad123

4. Ensure that the scope `openid`, `email` and `profile` is included in the`scopes` property. Then UAA shadow user (if addShadowUserOnLogin=true) is created
   with all properties. 

5. Restart UAA. You will see `Login with IAS-Public` link on your login page.
