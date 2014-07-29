<link href="https://raw.github.com/clownfart/Markdown-CSS/master/markdown.css" rel="stylesheet"></link>
# CloudFoundry User Account and Authentication (UAA) Server

[![Build Status](https://travis-ci.org/cloudfoundry/uaa.svg?branch=develop)](https://travis-ci.org/cloudfoundry/uaa)
[![Coverage Status](https://coveralls.io/repos/cloudfoundry/uaa/badge.png?branch=develop)](https://coveralls.io/r/cloudfoundry/uaa?branch=develop)

The UAA is the identity management service for Cloud Foundry.  It's
primary role is as an OAuth2 provider, issuing tokens for client
applications to use when they act on behalf of Cloud Foundry users.
It can also authenticate users with their Cloud Foundry credentials,
and can act as an SSO service using those credentials (or others).  It
has endpoints for managing user accounts and for registering OAuth2
clients, as well as various other management functions.

## Co-ordinates

* Tokens: [A note on tokens, scopes and authorities](https://github.com/cloudfoundry/uaa/tree/master/docs/UAA-Tokens.md)
* Technical forum: [vcap-dev google group](https://groups.google.com/a/cloudfoundry.org/forum/?fromgroups#!forum/vcap-dev)
* Docs: [docs/](https://github.com/cloudfoundry/uaa/tree/master/docs)
* API Documentation: [UAA-API.rst](https://github.com/cloudfoundry/uaa/tree/master/doc/UAA-API.rst)
* Specification: [The Oauth 2 Authorization Framework](http://tools.ietf.org/html/rfc6749)
* LDAP: [UAA LDAP Integration](https://github.com/cloudfoundry/uaa/tree/master/doc/UAA-LDAP.md)

## Quick Start

If this works you are in business:

    $ git clone git://github.com/cloudfoundry/uaa.git
    $ ./gradlew run

The apps all work together with the apps running on the same port
(8080) as `/uaa`, `/app` and `/api`.

### Deploy to Cloud Foundry

You can also build the app and push it to Cloud Foundry, e.g.

    $ ./gradlew :cloudfoundry-identity-uaa:war
    $ cf push myuaa -m 512M -p uaa/build/libs/cloudfoundry-identity-uaa-1.8.0.war --no-start
    $ cf set-env myuaa SPRING_PROFILES_ACTIVE default
    $ cf start myuaa

In the steps above, replace:
  
* `myuaa` with a unique application name
* `1.8.0` with the appropriate version label from your build

### Demo of command line usage on local server

First run the UAA server as described above:

    $ ./gradlew run

Then start another terminal and from the project base directory,  ask
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
ruby 1.9, then

    $ gem install cf-uaac
    $ uaac target http://localhost:8080/uaa
    $ uaac token get marissa koala

(or leave out the username / password to be prompted).

This authenticates and obtains an access token from the server using
the OAuth2 implicit grant, similar to the approach intended for a
client like CF. The token is stored in `~/.uaac.yml`, so dig into
that file and pull out the access token for your `cf` target (or use
`--verbose` on the login command line above to see it logged to your
console).

Then you can login as a resource server and retrieve the token
details:

    $ uaac target http://localhost:8080/uaa
    $ uaac token decode [token-value-from-above]
    
You should see your username and the client id of the original
token grant on stdout, e.g.

      exp: 1355348409
      user_name: marissa
      scope: cloud_controller.read openid password.write scim.userids tokens.read tokens.write
      email: marissa@test.org
      aud: scim tokens openid cloud_controller password
      jti: ea2fac72-3f51-4c8f-a7a6-5ffc117af542
      user_id: ba14fea0-9d87-4f0c-b59e-32aaa8eb1434
      client_id: cf

### Demo of command line usage on run.pivotal.io

The same command line example should work against a UAA running on
run.pivotal.io (except for the token decoding bit because you won't
have the client secret). In this case, there is no need to run a local
uaa server, so simply ask the external login endpoint to tell you
about the system:

    $ curl -H "Accept: application/json" login.run.pivotal.io
    {
      "prompts":{"username":["text","Username"],
        "password":["password","Password"]
      }
    }
    
You can then try logging in with the UAA ruby gem.  Make sure you have ruby 1.9, then

    $ gem install cf-uaac
    $ uaac target uaa.run.pivotal.io
    $ uaac token get [yourusername] [yourpassword]

(or leave out the username / password to be prompted).

This authenticates and obtains an access token from the server using the OAuth2 implicit
grant, the same as used by a client like CF.

## Integration tests

You can run the integration tests with

    $ ./gradlew integrationTest

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
  
These profiles set the `CLOUD_FOUNDRY_CONFIG_PATH` to pick up a
`uaa.yml` and (if appropriate) set the context root for running the
server (see below for more detail on that).

### Custom YAML Configuration

To modify the runtime parameters you can provide a `uaa.yml`, e.g.

    $ cat > /tmp/uaa.yml
    uaa:
      host: uaa.appcloud21.dev.mozycloud
      test:
        username: dev@cloudfoundry.org # defaults to vcap_tester@vmware.com
        password: changeme
        email: dev@cloudfoundry.org

then from `uaa/uaa`

    $ CLOUD_FOUNDRY_CONFIG_PATH=/tmp mvn test
    
The webapp looks for a Yaml file in the following locations
(later entries override earlier ones) when it starts up.

    classpath:uaa.yml
    file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml
    file:${UAA_CONFIG_FILE}
    ${UAA_CONFIG_URL}

### Using Maven with Cloud Foundry

To test against a Cloud Foundry instance use the Maven profile `vcap` (it
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

* `UAA_ADMIN_CLIENT_SECRET` the client secret for bootstrapping client
  registrations
  
All other settings from `uaa.yml` can be overridden individually as
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

### Using Maven to test with postgresql or mysql

The default uaa unit tests (mvn test) use hsqldb.

To run the unit tests using postgresql:

    $ SPRING_PROFILES_ACTIVE=test,postgresql CLOUD_FOUNDRY_CONFIG_PATH=src/test/resources/test/profiles/postgresql mvn test

To run the unit tests using mysql:

    $ SPRING_PROFILES_ACTIVE=test,mysql CLOUD_FOUNDRY_CONFIG_PATH=src/test/resources/test/profiles/mysql mvn test

The database configuration for the common and scim modules is located at:
common/src/test/resources/(mysql|postgresql).properties
scim/src/test/resources/(mysql|postgresql).properties

## Inventory

There are actually several projects here, the main `uaa` server application and some samples:

0. `common` is a module containing a JAR with all the business logic.  It is used in
the webapps below.

1. `uaa` is the actual UAA server

2. `api` (sample) is an OAuth2 resource service which returns a mock list of deployed apps

3. `app` (sample) is a user application that uses both of the above

4. `scim` [SCIM](http://www.simplecloud.info/) user management module used by UAA

In CloudFoundry terms

* `uaa` provides an authentication service plus authorized delegation for
   back-end services and apps (by issuing OAuth2 access tokens).

* `api` is a service that provides resources that other applications may
  wish to access on behalf of the resource owner (the end user).

* `app` is a webapp that needs single sign on and access to the `api`
  service on behalf of users.

## UAA Server

The authentication service is `uaa`. It's a plain Spring MVC webapp.
Deploy as normal in Tomcat or your container of choice, or execute
`mvn tomcat7:run` to run it directly from `uaa` directory in the source
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

### Use Cases

1. Authenticate

        GET /login

    A basic form login interface.

2. Approve OAuth2 token grant

        GET /oauth/authorize?client_id=app&response_type=code...

    Standard OAuth2 Authorization Endpoint.

3. Obtain access token

        POST /oauth/token

    Standard OAuth2 Authorization Endpoint.

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

     mvn -Dspring.profiles.active=hsqldb tomcat7:run

Or to use PostgreSQL instead of HSQL:

     mvn -Dspring.profiles.active=postgresql tomcat7:run

To bootstrap a microcloud type environment you need an admin client.
For this there is a database initializer component that inserts an
admin client.  If the default profile is active (i.e. not
`postgresql`) there is also a `cf` client so that the gem login works
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

Run it using `mvn tomcat7:run` from the `api` directory (once all other
tomcat processes have been shutdown). This will deploy the app to a
Tomcat manager on port 8080.

## The App Application

This is a user interface app (primarily aimed at browsers) that uses
OpenId Connect for authentication (i.e. SSO) and OAuth2 for access
grants.  It authenticates with the Auth service, and then accesses
resources in the API service.  Run it with `mvn tomcat7:run` from the
`app` directory (once all other tomcat processes have been shutdown).

The application can operate in multiple different profiles according
to the location (and presence) of the UAA server and the Login
application.  By default it will look for a UAA on
`localhost:8080/uaa`, but you can change this by setting an
environment variable (or System property) called `UAA_PROFILE`.  In
the application source code (`src/main/resources`) you will find
multiple properties files pre-configured with different likely
locations for those servers.  They are all in the form
`application-<UAA_PROFILE>.properties` and the naming convention
adopted is that the `UAA_PROFILE` is `local` for the localhost
deployment, `vcap` for a `vcap.me` deployment, `staging` for a staging
deployment (inside VMware VPN), etc.  The profile names are double
barrelled (e.g. `local-vcap` when the login server is in a different
location than the UAA server).

### Use Cases

1. See all apps

        GET /app/apps

    browser is redirected through a series of authentication and
    access grant steps (which could be slimmed down to implicit steps
    not requiring user at some point), and then the list of apps is shown.

2. See the currently logged in user details, a bag of attributes
grabbed from the open id provider

        GET /app

# Contributing to the UAA

Here are some ways for you to get involved in the community:

* Get involved with the Cloud Foundry community on the mailing lists.
  Please help out on the
  [mailing list](https://groups.google.com/a/cloudfoundry.org/forum/?fromgroups#!forum/vcap-dev)
  by responding to questions and joining the debate.
* Create [github](https://github.com/cloudfoundry/uaa/issues) tickets for bugs and new features and comment and
  vote on the ones that you are interested in.
* Github is for social coding: if you want to write code, we encourage
  contributions through pull requests from
  [forks of this repository](http://help.github.com/forking/).  If you
  want to contribute code this way, please reference an existing issue
  if there is one as well covering the specific issue you are
  addressing.  Always submit pull requests to the "develop" branch.
* Watch for upcoming articles on Cloud Foundry by
  [subscribing](http://blog.cloudfoundry.org) to the cloudfoundry.org
  blog
