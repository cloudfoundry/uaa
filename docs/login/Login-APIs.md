- [Login Server APIs](#login-server-apis)
	- [Overview](#overview)
	- [Login Form: ``GET /login``](#login-form-get-login)
	- [Form Login: `POST /login.do`](#form-login-post-logindo)
	- [Logout: `GET /logout.do`](#logout-get-logoutdo)
	- [OAuth2 Endpoints](#oauth2-endpoints)
		- [Start Authorization: `GET /oauth/authorize`](#start-authorization-get-oauthauthorize)
		- [Obtain Authorization Code: `POST /oauth/authorize`](#obtain-authorization-code-post-oauthauthorize)
		- [Token Endpoint: `POST /oauth/token`](#token-endpoint-post-oauthtoken)
	- [Login Info: `GET /login`](#login-info-get-login)
	- [Healthz: `GET /healthz`](#healthz-get-healthz)
	- [Autologin](#autologin)
		- [Obtain Autologin Code: `POST /autologin`](#obtain-autologin-code-post-autologin)

# Login Server APIs

## Overview

The Login Server:

* is separate from the UAA but needs to be connected to one via HTTP(S)
* provides SSO for web applications in the Cloud Foundry platform
* manages and provides a branded HTML UI for authentication and OAuth
  approval
* provides some other features via JSON APIs

## Login Form: ``GET /login``

Request: `GET /login?error={error}`  
Response Body: form with all the relevant prompts  
Response Codes: `200 - Success`  

## Form Login: `POST /login.do`

Browser POSTs to `/login.do` with user credentials (same as UAA).
Login Server returns a cookie that can be used to authenticate future
requests (until the session expires or the user logs out).

To use this endpoint, a Cross-Site Request Forgery (CSRF) token needs to first
be received from ``GET /login``, which will set it as a response cookie called ``X-Uaa-Csrf``.  Furthermore, the following headers are required in the POST for successful authentication:

| Header        | Value            |
| ------------- | ----------------:|
| Accept        | application/json |
| Content-Type  | application/x-www-form-urlencoded  |
| Referer       | http://login.cloudfoundry.example.com/login |

The raw data for the request must be submitted in the following format and must include the CSRF token (sample below):
```
'username=admin&password=mypassword&X-Uaa-Csrf=abcdef'
```
Finally, in addition to being submitted as part of the raw data, the CSRF token must also be added to the POST request as a cookie, also named ``X-Uaa-Csrf``.
## Logout: `GET /logout.do`

The Login Server is a Single Sign On server for the Cloud Foundry
platform (and possibly user apps as well), so if a user logs out, he
logs out of all the apps.  Users need to be reminded of the
consequences of their actions, so the recommendation for application
authors is to

* provide a local logout feature specific to the client application
  and use that to clear state in the client
* on the success page for that logout provide a link to the Login
  Server logout endpoint with a message telling the user what will
  happen if he clicks it
* provide a redirect in the link to the logout endpoint (see below) so
  that the user comes back to a familiar place when logged out,
  otherwise he will just get the logged-out success page from the
  Login Server

Request: `GET /logout.do?redirect=http://myclient/loggedout`  
Request Headers: `Cookie: JSESSIONID=8765FDUAYSFT7897`  
Response Codes:  

    200 - OK (if no redirect supplied)
    302 - FOUND (if redirect supplied)

## OAuth2 Endpoints

The standard authorize and token endpoints are available on the Login
Server.  They are passed through the request to the UAA, getting JSON
responses from the UAA and re-rendering them if the user requested
HTML.

### Start Authorization: `GET /oauth/authorize`

Client applications usually send a redirect to the user's browser with the
request URI appropriate to the Client.  Exactly the same as the UAA,
but the response is rendered differently.

Request: example  

    GET /oauth/authorize?response_type=code&
      redirect_uri=https://myclient/callback&
      client_id=myclient&
      state=RANDOM

The request must be authenticated as a user, so usually a session
cookie (`JSESSIONID`) is required, having been obtained previously
through the Login page.

### Obtain Authorization Code: `POST /oauth/authorize`

Exactly the same as the UAA.  When user approves the browser sends
`user_oauth_approval=true` (or false) and the Login Server sends back
an authorization code (if one was previously requested).

### Token Endpoint: `POST /oauth/token`

Obtain an access token, typically either with an authorization code or
client credentials.  Exactly the same as the UAA.

## Login Info: `GET /login`

Reports basic information about the build (version and git commit id)
and also passes through the information about prompts from the UAA.
Unauthenticated.

## Healthz: `GET /healthz`

Returns "ok" in the response body if the server is up and running

## Autologin

For user-facing account management UIs (e.g., portal) that need to set
or reset users' passwords, it is convenient to be able to log them in
immediately, rather than waiting for them to come back to the Login
Server and enter the new password explicitly.

1. Client POSTs user credentials to `/autologin`

2. Login Server responds with autologin code (short-lived, one-time)

3. Client builds redirect URI to Login Server `/authorize` endpoint
(normal OAuth2 auth code flow) appending the code

4. Client sends redirect to User

5. User's browser initiates auth code flow

6. Login Server redeems autologin code and exchanges it for an
authenticated user (as if the user had authenticated with the Login
Server manually)

7. User's browser now has SSO cookie for Login Server and remains
logged in for the duration of that session.

### Obtain Autologin Code: `POST /autologin`

Gets a short-lived code that can be exchanged for an authentication at
the Login Server `/oauth/authorize` UI.  The client authenticates
itself with its secret using an HTTP Basic header.

Request: `POST /autologin`  
Request Body: Form encoded user credentials  

    username=<username>&password=<password>

Request Headers:  

    Authorization: Basic <...>

Response Body:

    { "code"="aiuynklj", "path"="/oauth/authorize" }

By default, the password is required and is checked using the
`login.do` endpoint at the UAA, but could be made optional or changed
to other authentication credentials with a configuration change in the
Login Server (by adding a different `AuthenticationManager` to the
`AutologinController`).

The autologin code can also be used to establish the user session without hitting
/oauth/authorize. The code obtained above in step 1 can be used to perform a GET to
`/autologin`. This logs the user in for the duration of the session.
