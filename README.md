# Proof of Concept for Bento/LDAP Spring Security OAuth

## Quick Start

Quick demo of command line usage:

    $ git clone git://github.com/vmware-ac/poc-identity.git
    $ cd poc-identity

    $ export API=dsyerapi.cloudfoundry.com
    $ export AUTH=dsyerauth.cloudfoundry.com

    $ ./login.sh $AUTH -scope read_vcap

Enter your `api.cloudfoundry.com` credentials, and you should find
that you are authenticated.  There is an OAUth2 token stored in a
local file `.access_token`.  So you can read some resources on the
server:

    $ ./get.sh $API/services

You should get back a JSON list of your services (or try `/apps` if
you don't actually have any services).

Note the the local `.access_token` is not the VMC authorization token,
it is an OAuth2 token with restricted scope (you should get access
denied if you try and POST to an `$API` resource).  The VMC token is
stored in a shared database on the backend.

## A VMC Proxy

Now do this:

    $ vmc target dsyerapi.cloudfoundry.com
    $ vmc login dsyer@vmware.com  # use your own credentials

and you are all set to use `vmc` over OAuth2.  The login command in
this case gave you `scope=read_vcap,write_vcap`.

## Inventory

There are actually several projects here:

1. `auth` is an OAuth2 authorization service, and also an OpenID
provider.

2. `api` is an OAuth2 resource service

3. `app` is a user application that uses both of the above

4. `collaboration` is a draft implementation of the "Collaboration
Spaces Model" for CloudFoundry.  Used by the `api` service.

5. `env` is a very basic Ruby webapp used to investigate Ruby idioms
for webapp security

The three Java webapps are deployed on CloudFoundry:

* `app` = http://dsyerapp.cloudfoundry.com
* `api` = http://dsyerapi.cloudfoundry.com
* `auth` = http://dsyerauth.cloudfoundry.com

In CloudFoundry terms

* `auth` is the Auth Service providing single sign on, plus authorized
  delegation for back-end services and apps.

* `api` is `api.cloudfoundry.com` - it's a service that knows about
  the collaboration spaces.  N.B. *only* this component needs to know
  about the collaboration spaces.

* `app` is `code.cloudfoundry.com` or `studio.cloudfoundry.com` - a
  webapp that needs single sign on and access to the `api` service on
  behalf of users

## Preconditions

* The OAuth provider apps (`api` and `auth`) in this demo use a
relational database for sharing OAuth2 tokens.  If you open them up as
Maven projects in Eclipse (STS) then the `*.launch` files in the `api`
module can be used to launch a database (`hsql-server.launch`) and a
UI (`hsql-manager.launch`).  Right click and `Run As...`.  On
CloudFoundry they can just share a mysql service.
Alternatively, the database can be run using `mvn -e -P rundb exec:java`.

* While this isn't necessarily relevant to all use cases, clients
should follow instructions from the server about cookies (in
particular `JSESSIONID`).  You can use `curl -b ... -c ...` to do this
automatically.

* Clients should follow redirects where instructed, e.g. using `curl
  -L` (or a browser).

## The Auth Application

The authentication service is `auth`.  It's a plain Spring MVC webapp,
deploy as normal in Tomcat or your container of choice.

### Use Cases / Resources

Use `Accept: application/json` to get JSON responses, or `text/html`
to get (filename extensions `.json` and `.html` also work partially).

1. Login: 

        GET /login
        POST /login.do?j_username=marissa@vmware.com&j_password=koala

2. Logout:

        GET /auth/logout.do

3. Home page (for authenticated users):

        GET /auth/
        GET /auth/home

4. Get an access token directly using username/password.  

        GET /auth/oauth/authorize?grant_type=password

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

1. List photos

        GET /api/photos
        Authorization: Bearer ...
        Accept: application/json

  Example command line: 

        $ curl -v localhost:8080/api/photos -H "Authorization: Bearer ..."

2. Grab specific JPG image (binary data)

        GET /api/photos/{id}
        Authorization: Bearer ...
        Accept: image/jpeg

3. Get VCAP info (no auth header required)

        GET /info
        Accept: application/json

4. Get other VCAP stuff, e.g.

        GET /apps
        Authorization: Bearer ...
        Accept: application/json

  lists the apps.  This service is just a proxy for `vcap` now.
    
4. Post other VCAP stuff, e.g.

        POST /apps
        Authorization: Bearer ...
        Accept: application/json

To GET a CloudFoundry resource you need `scope=read_vcap` in your
OAuth2 authorization.  To POST, DELETE, PUT you need
`scope=write_vcap`.  To do both you need `scope=write_vcap,read_vcap`.
    
## The App Application

This is a user interface (primarily aimed at browser) app that uses
OpenID for authentication (i.e. SSO) and OAuth2 for access grants.  It
authenticates with the Auth service, and then accesses resources in
the API service.

### Use Cases

1. See all photos

        GET /app/photos		

  browser is redirected through a series of authentication and access
  grant steps (which could be slimmed down to implicit steps not
  requiring user at some point), and then the photos are shown.

2. See an individual photo

        GET /app/photos/{id}

  If the useer is already authenticated goes straight to the image,
  delegating to the API service to get the actual bytes.  The app is
  acting as a simple proxy for the API service in this case.

3. See the currently logged in user details, a bag of attributes
grabbed from the open id provider

    GET /app

### Command line usage:

Local set up:

    $ export APP=localhost:8080/app
    $ export AUTH=http://localhost:8080/auth

Cloudfoundry set up:

    $ export APP=dsyerapp.cloudfoundry.com
    $ export AUTH=dsyerauth.cloudfoundry.com

Then

    $ get() { location=$1; shift; curl -b ~/tmp/cookies.txt -c ~/tmp/cookies.txt -v -H "Accept: application/json; */*" $location $*; echo; }
    $ mkdir ~/tmp
    $ rm ~/tmp/cookies.txt

There are 4 requests to authenticate and get back to the original
saved request:

    $ get $APP -L
    $ get $APP/j_spring_openid_security_check -d action=verify -d openid_identifier=$AUTH/openid/xrds -L
    $ get $AUTH/login.do -d j_username=marissa@vmware.com -d j_password=koala -L
    $ get $AUTH/openid/authorize -d approve=true -L

## The Env Application

A simple Ruby (Sinatra) application which is a client of the `api`
resource service.  Prerequisites: 

    $ gem install sinatra oauth2

`oauth2` needs a newish version of gem, so you might have to `rvm use 1.9.2` to get it to install. Runs from the command line:

    $ (cd env; ruby env.rb)

Make sure the `auth` and `api` applications are running on port 8080 and visit
[http://localhost:4567/auth](http://localhost:4567/auth) to see the OAuth dance
produce some output (e.g. list of photos from `api`), after authenticating and
authorizing at `auth`.  Use a browser to make it automatic, or use curl and
follow redirects.
