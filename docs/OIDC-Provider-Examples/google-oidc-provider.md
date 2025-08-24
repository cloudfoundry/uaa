# Registering google as external OAuth provider in UAA
 
Google can be setup as an OIDC provider for UAA. 

1. Establish OAuth client in Google. Add the following URI to the authorized redirect URIs section: http://{UAA_HOST}/login/callback/{origin}. Additional Google documentation for achieving this can be found here: https://developers.google.com/identity/protocols/OAuth2

2. Make sure you have `Client ID` and `Client secret`.

3. The following configuration needs to be added in login.yml. 
Please refer to 'https://accounts.google.com/.well-known/openid-configuration' for authUrl and tokenUrl
  ```
  login:
    oauth:
      providers:
        google:
          type: oidc1.0
          authUrl: https://accounts.google.com/o/oauth2/v2/auth
          tokenUrl: https://www.googleapis.com/oauth2/v4/token
          tokenKeyUrl: https://www.googleapis.com/oauth2/v3/certs
          issuer: https://accounts.google.com
          redirectUrl: http://localhost:8080/uaa
          scopes:
            - openid
            - email
          linkText: Login with google
          showLinkText: true
          addShadowUserOnLogin: true
          relyingPartyId: REPLACE_WITH_CLIENT_ID
          relyingPartySecret: REPLACE_WITH_CLIENT_SECRET
          clientAuthInBody: true
          skipSslValidation: false
          attributeMappings:
            user_name: email
  ```

4. Ensure that the scope `email` is included in the`scopes` property. Without this, UAA will not be able to identify the authenticated user

5. Ensure that `issuer` host matches the host in the token claims. In this case, it is the same host as `authurl`

6. Restart UAA. You will see `Login with google` link on your login page.
