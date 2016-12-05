<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Registering google as external OAuth provider in UAA](#registering-google-as-external-oauth-provider-in-uaa)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Registering google as external OAuth provider in UAA
 
Google can be setup as an OIDC provider for UAA. 

1. Establish OAuth client in Google. Add following URI to the authorized redirect URIs section: http://{UAA_HOST}/login/callback/{origin}

2. Make sure you have `Client ID` and `Client secret`.

2. The following configuration needs to be added in login.yml. 
Please refer to 'https://accounts.google.com/.well-known/openid-configuration' for authUrl and tokenUrl
  ```
  login:
    oauth:
      providers:
        google:
          type: oidc1.0
          authUrl: https://accounts.google.com/o/oauth2/v2/auth
          tokenUrl: https://www.googleapis.com/oauth2/v4/token
          issuer: https://accounts.google.com
          redirectUrl: http://localhost:8080/uaa
          scopes:
            - openid
            - email
          linkText: Login with google
          showLinkText: true
          addShadowUserOnLogin: true
          relyingPartyId: `Client ID`
          relyingPartySecret: `Client secret`
          skipSslValidation: false
          attributeMappings:
            user_name: email
  ```

4. Ensure that the scope `email` is included in the`scopes` property. Without this, UAA will not be able to identify the authenticated user

5. Ensure that `issuer` host matches the host in the token claims. In this case, it is the same host as `authurl`

6. Restart UAA. You will see `Login with google` link on your login page.
