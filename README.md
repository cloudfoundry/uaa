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
(8080) as `/uaa`, `/app` and `/api`.  You can probably use Maven 2.2.1
to build the code, but you need to use Maven 3 if you want to run the
server from the command line (or run integration tests).

### Demo of command line usage

First run the uaa server as described above:

    $ cd uaa
    $ mvn tomcat:run

Then start another terminal and from the project base directory, and ask
the login endpoint to tell you about the system:

    $ curl -H "Accept: application/json" localhost:8080/uaa/login
    {
      "timestamp":"2012-03-28T18:25:49+0100",
      "commit_id":"111274e",
      "prompts":{"username":["text","Username"],
        "password":["password","Password"]
      }
    }
    
Then you can try logging in with the UAA ruby gem.  Make sure you have
ruby 1.9, and bundler installed, then

    $ (cd gem/; bundle)
    $ ./gem/bin/uaa target localhost:8080/uaa
    $ ./gem/bin/uaa login marissa koala

(or leave out the username / password to be prompted).

This authenticates and obtains an access token from the server using
the OAuth2 implicit grant, similar to the approach intended for a
client like VMC. The token is returned in stdout, so copy paste the
value into this next command:

    $ ./gem/bin/uaa --client-id=admin --client-secret=adminclientsecret decode
    
and you should see your username and the client id of the original
token grant on stdout.

## Integration tests

With all apps deployed into a running server on port 8080 the tests
will include integration tests (a check is done before each test that
the app is running).  You can deploy them in your IDE or using the
command line with `mvn tomcat:run` and then run the tests as normal.

For individual modules, or for the whole project, you can also run
integration tests and the server from the command line in one go with

    $ mvn test -P integration

(This might require an initial `mvn install` from the parent directory
to get the wars in your local repo first.)

To make the tests work in various environments you can modify the
configuration of the server and the tests (e.g. the admin client)
using a variety of mechanisms. The simplest is to provide additional
Maven profiles on the command line, e.g.

    $ (cd uaa; mvn test -P vcap)
    
will run the integration tests against a uaa server running in a local
vcap, so for example the service URL is set to `uaa.vcap.me` (by
default).  There are several Maven profiles to play with, and they can
be used to run the server, or the tests or both:

* `local`: runs the server on the ROOT context `http://localhost:8080/`

* `vcap`: also runs the server on the ROOT context and points the
  tests at `uaa.vcap.me`.
  
* `devuaa`: points the tests at `http://devuaa.cloudfoundry.com` (an
  instance of UAA deployed on cloudfoundry).
  
All these profiles set the `CLOUD_FOUNDRY_CONFIG_PATH` to pick up a
`uaa.yml` and (if appropriate) set the context root for running the
server (see below for more detail on that).

### BVTs

There is a really simple cucumber feature spec (`--tag @uaa`) to
verify that the UAA server is there.  There is also a rake task to
launch the integration tests from the `uaa` submodule in `vcap`.
Typical usage for a local (`uaa.vcap.me`) instance:

    $ cd vcap/tests
    $ rake bvt:run_uaa

You can change the most common important settings with environment
variables (see below), or with a custom `uaa.yml`. N.B. `MAVEN_OPTS`
cannot be used to set JVM system properties for the tests, but it can
be used to set memory limits for the process etc.

### Custom YAML Configuration

To modify the runtime parameters you can provide a `uaa.yml`, e.g.

    $ cat > /tmp/uaa.yml
    uaa:
      host: uaa.appcloud21.dev.mozycloud
      test:
        username: dev@cloudfoundry.org # defaults to vcap_tester@vmware.com
        password: changeme
        email: dev@cloudfoundry.org

then from `vcap-tests`

    $ CLOUD_FOUNDRY_CONFIG_PATH=/tmp rake bvt:run_uaa
    
or from `uaa/uaa`

    $ CLOUD_FOUNDRY_CONFIG_PATH=/tmp mvn test
    
The integration tests look for a Yaml file in the following locations
(later entries override earlier ones), and the webapp does the same
when it starts up so you can use the same config file for both:

    classpath:uaa.yml
    file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml
    file:${UAA_CONFIG_FILE}
    ${UAA_CONFIG_URL}

### Using Maven with Cloud Foundry or VCAP

To test against a vcap instance use the Maven profile `vcap` (it
switches off some of the tests that create random client and user
accounts):

    $ (cd uaa; mvn test -P vcap)

To change the target server it should suffice to set
`VCAP_BVT_TARGET` (the tests prefix it with `uaa.` to form the
server url), e.g.

    $ VCAP_BVT_TARGET=appcloud21.dev.mozycloud mvn test -P vcap

You can also override some of the other most important default
settings using environment variables.  The defaults as usual come from
`uaa.yml` but tests will search first in an environment variable:

* `UAA_ADMIN_CLIENT_ID` the client id for bootstrapping client
  registrations needed for the rest of the tests.

* `UAA_ADMIN_CLIENT_SECRET` the client secret for boottrapping client
  registrations
  
All other settings from `uaa.yml` can be overriden individually as
system properties.  Running in an IDE this is easy just using whatever
features allow you to modify the JVM in test runs, but using Maven you
have to use the `argLine` property to get settings passed onto the
test JVM, e.g.

    $ mvn -DargLine=-Duaa.test.username=foo test
    
will create an account with `userName=foo` for testing (instead using
the default setting from `uaa.yml`).

If you prefer environment variables to system properties you can use a
custom `uaa.yml` with placeholders for your environment variables,
e.g.

    uaa:
      test:
        username: ${UAA_TEST_USERNAME:marissa}

will look for an environment variable (or system property)
`UAA_TEST_USERNAME` before defaulting to `marissa`.  This is the trick
used to expose `UAA_ADMIN_CLIENT_SECRET` etc. in the standard
configuration.

## Inventory

There are actually several projects here, the main `uaa` server application and some samples:

0. `common` is a module containing a JAR with all the business logic.  It is used in
the webapps below.

1. `uaa` is the actual UAA server

2. `gem` is a ruby gem (`cf-uaa-client`) for interacting with the UAA server

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
`mvn tomcat:run` to run it directly from `uaa` directory in the source
tree (make sure the common jar is installed first using `mvn install`
from the common subdirectory or from the top level directory).  When
running with maven it listens on port 8080.

The UAA Server supports the APIs defined in the UAA-APIs document. To summarise:

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
Maven profile `local` to launch with context root `/`, and another
called `vcap` to launch at `/` with a postgresql backend.

### Configuration

There is a `uaa.yml` in the application which provides defaults to the
placeholders in the Spring XML.  Wherever you see
`${placeholder.name}` in the XML there is an opportunity to override
it either by providing a System property (`-D` to JVM) with the same
name, or a custom `uaa.yml` (as described above).

All passwords and client secrets in the config files are plain text,
but they will be inserted into the UAA database encrypted with BCrypt.

### User Account Data

The default is to use an in-memory RDBMS user store that is
pre-populated with a single test users: `marissa` has password
`koala`.

To use Postgresql for user data, activate one of the Spring profiles
`hsqldb` or `postgresql`.

The active profiles can be configured in `uaa.yml` using

    spring_profiles: postgresql
    
or by passing the `spring.profiles.active` parameter to the JVM. For,
example to run with an embedded HSQL database:

     mvn -Dspring.profiles.active=hsqldb tomcat:run

Or to use PostgreSQL instead of HSQL:

     mvn -Dspring.profiles.active=postgresql tomcat:run

To bootstrap a microcloud type environment you need an admin client.
For this there is a database initializer component that inserts an
admin client.  If the default profile is active (i.e. not
`postgresql`) there is also a `vmc` client so that the gem login works
out of the box.  You can override the default settings and add
additional clients in `uaa.yml`:

    oauth:
      clients:
        admin:    
          authorized-grant-types: client_credentials
          scope: read,write,password
          authorities: ROLE_CLIENT,ROLE_ADIN
          id: admin
          secret: adminclientsecret
          resource-ids: clients

The admin client can be used to create additional clients (but not to
do anything much else).  A client with read/write access to the `scim`
resource will be needed to create user accounts.  The integration
tests take care of this automatically, inserting client and user
accounts as necessary to make the tests work.

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
