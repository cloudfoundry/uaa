<link href="https://raw.github.com/clownfart/Markdown-CSS/master/markdown.css" rel="stylesheet"></link>
# CloudFoundry User Account and Authentication (UAA) Server

## Co-ordinates

* Team:
  * Dale Olds (`olds@vmware.com`)
  * Dave Syer (`dsyer@vmware.com`)
  * Luke Taylor (`ltaylor@vmware.com`)
  * Joel D'Sa (`jdsa@vmware.com`)
* Team mailing list: `cf-id@vmware.com`
* Docs: docs/

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

    $ ./gem/bin/uaa target localhost:8080/uaa
    $ ./gem/bin/uaa login marissa koala

(or leave out the username / password to be prompted).

This authenticates and obtains an access token from the server using the OAuth2 implicit
grant, similar to the approach intended for a client like VMC. The token is
returned in stdout, so copy paste the value into this next command:

    $ ./gem/bin --client_id=app --client_secret=appclientsecret decode <token>
    
and you should see your username and the client id of the original
token grant on stdout.

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

### BVTs

There is a really simple cucumber feature spec (`--tag @uaa`) to
verify that the UAS server is there.  There is also a rake task to
launch the integration tests from the `uaa` submodule in `vcap`.
Typical usage for a local (`uaa.vcap.me`) instance:

    $ cd vcap/tests
    $ rake bvt:run_uaa

To modify the runtime parameters you can provide a `uaa.yml` and set the
env var `CLOUD_FOUNDRY_CONFIG_PATH`, e.g.

    $ cat > /tmp/uaa.yml
    uaa:
      host: uaa.appcloud21.dev.mozycloud
      test:
        username: dev@cloudfoundry.org # defaults to vcap_tester@vmware.com
        password: changeme
        email: dev@cloudfoundry.org
    $ CLOUD_FOUNDRY_CONFIG_PATH=/tmp rake bvt:run_uaa

The tests will usually fail on the first run because of the 1 sec
granularity of the timestamp on the tokens in the cloud_controller (so
duplicate tokens will be rejected by the server). When you run the
second and subsequent times they should pass because new token values
will be obtained from the server.

You can also change individual properties on the command line with
`UAA_ARGS`, which are passed on to the mvn command line, or with
MAVEN_OPTS which are passed on to the shell executing mvn, e.g.

    $ UAA_ARGS=-Duaa=uaa.appcloud21.dev.mozycloud rake bvt:run_uaa

N.B. MAVEN_OPTS cannot be used to set JVM system properties for the tests, but it can be used to set memory limits for the process etc.

## Inventory

There are actually several projects here, the main `uaa` server application and some samples:

1. `uaa` is the actual UAA server

2. `gem` is a ruby gem (`cloudfoundry-uaa`) for interacting with the UAA server

3. `api` (sample) is an OAuth2 resource service which returns a mock list of deployed apps

4. `app` (sample) is a user application that uses both of the above

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

### Configuration

There is a `uaa.yml` in the application which provides defaults to the
placeholders in the Spring XML.  Wherever you see
`${placeholder.name}` in the XML there is an opportunity to override
it either by providing a System property (`-D` to JVM) with the same
name, or an environment-specific `uaa.yml` under
`env['CLOUD_FOUNDRY_CONFIG_PATH']/uaa.yml`.  When vcap is deployed the
`CLOUD_FOUNDRY_CONFIG_PATH` is defined according to the way it was
installed.

All passwords and client secrets in the config files must be encypted
using BCrypt.  In Java you can do it like this (with
`spring-securty-crypto` on the classpath):

    String password = BCrypt.hashpw("plaintext");

In ruby you can do it like this:

    require 'bcrypt'
    password = BCrypt::Password.create('plaintext')

### User Account Data

The default is to use an in-memory, hash-based user store that is
pre-populated with some test users: e.g. `dale` has password
`password` and `marissa` has password `koala`.

To use a RDBMS for user data, activate the Spring profiles `jdbc` and
one of `hsqldb` or `postgresql`.  The opposite is `!jdbc` which needs
to be specified explicitly if any other profiles are active.  The
`hsqldb` profile will start up with an in-memory RDBMS by default.

The active profiles can be configured by passing the
`spring.profiles.active` parameter to the JVM. For, example to run
with an embedded HSQL database:

     mvn -Dspring.profiles.active=jdbc,hsqldb,!legacy tomcat:run

Or to use PostgreSQL instead of HSQL:

     mvn -Dspring.profiles.active=jdbc,postgresql,!legacy tomcat:run

To bootstrap a microcloud type environment you need an admin user.
For this there is a database initializer component that inserts an
admin user if it finds an empty database on startup.  Override the
default settings (username/password=admin/admin) in `uaa.yml`:

    bootstrap:
      admin:
        username: foo
        password: $2a$10$yHj...
        email: admin@test.com
        family_name: Piper
        given_name: Peter

(the password has to be bcrypted).

### Legacy Mode

There is a legacy mode where the CF.com cloud controller is used for
the authentication and token generation.  To use this, launch the app
with Spring profile `legacy` (a Maven profile with the same name is
provided for convenience as well).  The opposite is `!legacy` which
needs to be specified explicitly if any other profiles are active.
The cloud controller login URL defaults to
`http://api.cloudfoundry.com/users/{username}/tokens` - to override it
provide a System property or `uaa.yml` entry for
`cloud_controller.login_url`.

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
