# CloudFoundry User Account and Authentication Server

## Quick Start

If this works you are in business:

    $ git clone git://github.com/vmware-ac/uaa.git
    $ cd uaa
    $ mvn install
	
Each module has a `mvn jetty:run` target, or you could import them as
projects into STS (use 2.8.0 or better if you can).  To work together
the apps run on different ports (8080=/uaa, 7080=/app, 9080=/api).

## Inventory

There are actually several projects here:

1. `auth` is an OAuth2 authorization service and authentication source

2. `api` is an OAuth2 resource service

3. `app` is a user application that uses both of the above

In CloudFoundry terms

* `auth` is the Auth Service providing single sign on, plus authorized
  delegation for back-end services and apps.

* `api` is like `api.cloudfoundry.com` - it's a service that knows
  about the collaboration spaces.  N.B. *only* this component needs to
  know about the collaboration spaces.

* `app` is `code.cloudfoundry.com` or `studio.cloudfoundry.com` - a
  webapp that needs single sign on and access to the `api` service on
  behalf of users

## The Auth Application

The authentication service is `auth`.  It's a plain Spring MVC webapp,
deploy as normal in Tomcat or your container of choice.

### Use Cases / Resources

Use `Accept: application/json` to get JSON responses, or `text/html`
to get (filename extensions `.json` and `.html` also work partially).

1. Login: 

        GET /login
        POST /login.do?username=marissa&password=koala

2. Logout:

        GET /auth/logout.do

3. Home page (for authenticated users):

        GET /auth/
        GET /auth/home

4. Get an access token directly using username/password.  

        GET /auth/oauth/token?grant_type=password

  Example command line:

        $ curl localhost:8080/auth/oauth/authorize?grant_type=password\&client_id=app\&username=marissa@vmware.com\&password=koala\&response_type=code\&scope=read_photos

  Example response:

        {
          "access_token": "4e14e7ba-ae73-4932-89cd-07692d3c7bc0",
          "expires_in": 43199,
          "refresh_token": "f0d5ccd5-e636-4be3-a35a-32325982723e"
        }

5. OpenID provider for SSO.  An OpenID consumer (e.g. `app`) can
authenticate via the XRDS at `/auth/openid/users/{user}`.

## The API Application

An example local resource service and also a proxy for the Cloud
Controller on `cloudfoundry.com`.  It hosts the photo service from
Spring Security OAuth (client id `app`) under `/photos` and delegates
all other requests to `api.cloudfoundry.com`.  You can use it as a raw
`vmc` target because although `vmc` doesn't know about OAuth2, the app
proxies all requests and translates an incoming OAuth2 header into a
native vcap header.

### Use Cases

All resources are protected by default and client should get a 403 or
401 if they are not authorized.  (N.B. the current implementation
redirects to a non-existent login page instead of throwing the
exception.  Maybe a redirect to the Auth service would be better.)
Authorization comes through the access token from the authorization
service provided in a header:

    Authorization: Bearer ...

1. List apps

        GET /api/photos
        Authorization: Bearer ...
        Accept: application/json

  Example command line: 

        $ curl -v localhost:8080/api/apps -H "Authorization: Bearer ..."

To GET a CloudFoundry resource you need `scope=read` in your
OAuth2 authorization.

## The App Application

This is a user interface (primarily aimed at browser) app that uses
OpenID for authentication (i.e. SSO) and OAuth2 for access grants.  It
authenticates with the Auth service, and then accesses resources in
the API service.

### Use Cases

1. See all apps

        GET /app/apps	

  browser is redirected through a series of authentication and access
  grant steps (which could be slimmed down to implicit steps not
  requiring user at some point), and then the photos are shown.

2. See the currently logged in user details, a bag of attributes
grabbed from the open id provider

        GET /app
