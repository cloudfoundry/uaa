<link href="https://raw.github.com/clownfart/Markdown-CSS/master/markdown.css" rel="stylesheet"></link>
# CloudFoundry User Account and Authentication (UAA) Server

## Co-ordinates

* Team: 
  * Dale Olds (`olds@vmware.com`)
  * Dave Syer (`dsyer@vmware.com`)
  * Luke Taylor (`ltaylor@vmware.com`)
  * Joel D'Sa (`jdsa@vmware.com`)
* Team mailing list: `cfid@vmware.com`
* Repository: [http://github.com/vmware-ac/uaa](http://github.com/vmware-ac/uaa)
* Issue tracker: [https://issuetracker.springsource.com/browse/CFID](https://issuetracker.springsource.com/browse/CFID)
* Docs: [http://github.com/vmware-ac/uaa/wiki](http://github.com/vmware-ac/uaa/wiki)

## Quick Start

If this works you are in business:

    $ git clone git@github.com:vmware-ac/uaa.git
    $ cd uaa
    $ mvn install

Each module has a `mvn tomcat:run` target to run individually, or you
could import them as projects into STS (use 2.8.0 or better if you
can).  The apps all work together the apps running on the same port
(8080) as `/uaa`, `/app` and `/api`.

### Demo of command line usage

First run the uaa server as described above:

    $ cd uaa
    $ mvn tomcat:run

Then start another terminal and from the project base directory, run:

    $ ./login.sh "localhost:8080/uaa"

And hit return twice to accept the default username and password.

This authenticates and obtains an access token from the server using the OAuth2 implicit
grant, similar to the approach intended for a client like VMC. The token is
stored in the file `.access_token`.

Now kill the `uaa` server and run the `api` server (which starts the
`uaa` server as well):

    $ cd samples/api
    $ mvn tomcat:run

And then (from the base directory) execute:

    $ ./get.sh http://localhost:8080/api/apps

which should return a JSON array of (pretend) running applications.

## Integration tests

With all apps deployed into a running server on port 8080 the tests
will include integration tests (a check is done before each test that
the app is running).  You can deploy them in your IDE or using the
command line with `mvn tomcat:run`.

For individual modules, or for the whole project, you can also run
integration tests from the command line in one go with

    $ mvn integration-test

(This might require an initial `mvn install` from the parent directory
to get the wars in your local repo first.)

## Inventory

There are actually several projects here, the main `uaa` server application and some samples:

1. `uaa` is the actual UAA server

2. `api` (sample) is an OAuth2 resource service which returns a mock list of deployed apps

3. `app` (sample) is a user application that uses both of the above

In CloudFoundry terms

* `uaa` provides an authentication service plus authorized delegation for
   back-end services and apps (by issuing OAuth2 access tokens).

* `api` is `api.cloudfoundry.com` - it's a service which provides resources
   which other applications may wish to access on behalf of the resource
   owner (the end user).

* `app` is `code.cloudfoundry.com` or `studio.cloudfoundry.com` - a
  webapp that needs single sign on and access to the `api` service on
  behalf of users.

## UAA Server

The authentication service is `uaa`. It's a plain Spring MVC webapp.
Deploy as normal in Tomcat or your container of choice, or execute
`mvn tomcat:run` to run it directly from `uaa` directory in the source tree.
When running with maven it listen on port 8080.

It supports the APIs defined in the UAA-APIs document. To summarise:

1. The OAuth2 /authorize and /token endpoints

2. A /login_info endpoint to allow querying for required login prompts

3. A /check_token endpoint, to allow resource servers to obtain information about
an access token submitted by an OAuth2 client.

4. SCIM user provisioning endpoint

5. OpenID connect endpoints to support authentication /userinfo and
/check_id (todo). Implemented roughly enough to get it working (so
/app authenticates here), but not to meet the spec.

Authentication can be performed by command line clients by submitting
credentials directly to the `/authorize` endpoint (as described in
UAA-API doc).  There is an `ImplicitAccessTokenProvider` in Spring
Security OAuth that can do the heavy lifting if your client is Java.

By default `uaa` will launch with a context root `/uaa`. There is a
Maven profile `vcap` to launch with context root `/`.

### User Account Data

The default is to use an in-memory, hash-based user store that is
pre-populated with some test users: e.g. `dale` has password
`password` and `marissa` has password `koala`.

To use a RDBMS for user data activate the Spring profiles `jdbc` and
one of `hsqldb` or `postgresql`.  The opposite is `!jdbc` which needs
to be specified explicitly if any other profiles are active.  The
`hsqldb` profile will start up with an in-memory RDBMS by default.
Warning: the database will start empty, so no users can log in until
the first account is created.

The active profiles can be configured by passing the
`spring.profiles.active` parameter to the JVM. For, example to run
with an embedded HSQL database:

     mvn -Dspring.profiles.active=jdbc,hsqldb,!private,!legacy tomcat:run

Or to use PostgreSQL instead of HSQL:

     mvn -Dspring.profiles.active=jdbc,postgresql,!private,!legacy tomcat:run
	
To bootstrap a microcloud type environment you need the SCIM user
endpoints to be unsecure so that a user can create an account and set
its password to bootstrap the system.  For this use the Spring profile
`private`.  The opposite is `!private` which needs to be specified
explicitly if any other profiles are active.

To launch in legacy mode with the CF.com cloud controller as the
authentication and token source use profile `legacy`.  The opposite is
`!legacy` which needs to be specified explicitly if any other profiles
are active.

## The API Application

An example resource server.  It hosts a service which returns
a list of mock applications under `/apps`.

Run it using `mvn tomcat:run` from the `api` directory (once all other
tomcat processes have been shutdown). This will deploy the app to a
Tomcat manager on port 8080.

## The App Application

This is a user interface app (primarily aimed at browsers) that uses
OpenId Connect for authentication (i.e. SSO) and OAuth2 for access
grants.  It authenticates with the Auth service, and then accesses
resources in the API service.  Run it with `mvn tomcat:run` from the
`app` directory (once all other tomcat processes have been shutdown).

### Use Cases

1. See all apps

        GET /app/apps

  browser is redirected through a series of authentication and access
  grant steps (which could be slimmed down to implicit steps not
  requiring user at some point), and then the photos are shown.

2. See the currently logged in user details, a bag of attributes
grabbed from the open id provider

        GET /app
