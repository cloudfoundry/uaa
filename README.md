# CloudFoundry User Account and Authentication (UAA) Server

## Quick Start

If this works you are in business:

    $ git clone git://github.com/vmware-ac/uaa.git
    $ cd uaa
    $ mvn install
	
Each module has a `mvn jetty:run` target, or you could import them as
projects into STS (use 2.8.0 or better if you can).  To work together
the apps run on different ports (8080=/uaa, 7080=/app, 9080=/api).

### Demo of command line usage

First run the uaa server as described above:

    $ cd uaa
    $ mvn jetty:run

Then start another terminal and from the project base directory, run:

    $ ./login.sh "localhost:8080/cloudfoundry-identity-uaa"

And hit return twice to accept the default username and password.

This authenticates and obtains an access token from the server using the OAuth2 implicit
grant, similar to the approach intended for a client like VMC. The token is
stored in the file `.access_token`.

Now run the `api` server:

    $ cd api
    $ mvn jetty:run

And then (from the base directory) execute:

    $ ./get.sh http://localhost:9080/cloudfoundry-identity-api/apps

which should return a JSON array of (pretend) running applications.

## Inventory

There are actually several projects here:

1. `uaa` is the actual UAA server

2. `api` is an OAuth2 resource service which returns a mock list of deployed apps

3. `app` is a user application that uses both of the above

In CloudFoundry terms

* `uaa` provides an authentication service plus authorized delegation for
   back-end services and apps (by issuing OAuth2 access tokens).

* `api` is `api.cloudfoundry.com` - it's a service which provides resources
   which other applications may wish to access on behalf of the resource
   owner (the end user).

* `app` is `code.cloudfoundry.com` or `studio.cloudfoundry.com` - a
  webapp that needs single sign on and access to the `api` service on
  behalf of users.

The authentication service is `uaa`. It's a plain Spring MVC webapp.
Deploy as normal in Tomcat or your container of choice, or execute
`mvn jetty:run` to run it directly from `uaa` directory in the source tree.
When running with maven it listen on port 8080.

It supports the APIs defined in the UAA-APIs document. To summarise:

1. The OAuth2 /authorize and /token endpoints

2. A /login_info endpoint to allow querying for required login prompts

3. A /check_token endpoint, to allow resource servers to obtain information about
an access token submitted by an OAuth2 client.

4. SCIM user provisioning endpoints (todo)

5. OpenID connect endpoints to support authentication
(todo). Implemented roughly enough to get it working (so /app
authenticates here), but not to meet the spec.

Authentication can be performed by command line clients by submitting
credentials directly to the /authorize endpoint (as described in
UAA-API doc).  There is an `ImplicitAccessTokenProvider` in Spring
Security OAuth that can do the heavy lifting.

## The API Application

An example resource server.  It hosts a service which returns
a list of mock applications under `/apps`.

Run it using `mvn jetty:run` from the `api` directory. This will start
the application on port 9080.

## The App Application

This is a user interface (primarily aimed at browser) app that uses
OpenId Connect for authentication (i.e. SSO) and OAuth2 for access
grants.  It authenticates with the Auth service, and then accesses
resources in the API service.

### Use Cases


1. See all apps

        GET /app/apps	

  browser is redirected through a series of authentication and access
  grant steps (which could be slimmed down to implicit steps not
  requiring user at some point), and then the photos are shown.

2. See the currently logged in user details, a bag of attributes
grabbed from the open id provider

        GET /app
