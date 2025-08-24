# Registering GitHub as an external OAuth provider in UAA

GitHub can be setup as an Oauth2 provider for UAA.

1. Create an OAuth “application” client in GitHub.
   For example at: `https://github.com/organizations/{YOUR-ORG}/settings/applications/new`.

   Add the following URI in the “_Authorization callback URL_” text field:
   `http://{UAA_HOST}/login/callback/{origin}`. Additional GitHub
   documentation for achieving this can be found here:
   [Creating an OAuth App](https://docs.github.com/en/free-pro-team@latest/developers/apps/creating-an-oauth-app)
   [Authorizing OAuth Apps](https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps)

2. Make sure you have `Client ID` and `Client secret`.

3. The following configuration needs to be added in login.yml.
   Please refer to 'https://accounts.google.com/.well-known/openid-configuration' for authUrl and tokenUrl

        login:
          oauth:
            providers:
              github:
                type: oauth2.0
                providerDescription: Github OAuth provider, using the 'Authorization Code Grant' flow
                authUrl: https://github.com/login/oauth/authorize
                tokenUrl: https://github.com/login/oauth/access_token
                userInfoUrl: https://api.github.com/user
                scopes:
                  - read:user
                  - user:email
                linkText: Login with Github
                showLinkText: true
                addShadowUserOnLogin: true # users won't need to be pre-populated into the UAA database prior to authenticating with Github
                relyingPartyId: REPLACE_WITH_CLIENT_ID
                relyingPartySecret: REPLACE_WITH_CLIENT_SECRET
                skipSslValidation: false
                clientAuthInBody: true
                attributeMappings:
                  given_name: login
                  family_name: name # Github doesn't split 'given_name' and 'family_name'
                  user_name: email

4. Ensure that the scope `email` is included in the`scopes` property. Without
   this, UAA will not be able to identify the authenticated user.

5. Restart UAA. You will see `Login with github` link on your login page.
