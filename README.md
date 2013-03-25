<link href="https://raw.github.com/clownfart/Markdown-CSS/master/markdown.css" rel="stylesheet"></link>
# CloudFoundry User Account and Authentication (UAA) Server

The UAA is the identity management service for Cloud Foundry.  It's
primary role is as an OAuth2 provider, issuing tokens for client
applications to use when they act on behalf of Cloud Foundry users.
It can also authenticate users with their Cloud Foundry credentials,
and can act as an SSO service using those credentials (or others).  It
has endpoints for managing user accounts and for registering OAuth2
clients, as well as various other management functions.

## Co-ordinates

* Team:
  * Dale Olds (`olds@vmware.com`)
  * Dave Syer (`dsyer@vmware.com`)
  * Luke Taylor (`ltaylor@vmware.com`)
  * Joel D'Sa (`jdsa@vmware.com`)
  * Vidya Valmikinathan
* Technical forum: [vcap-dev google group](https://groups.google.com/a/cloudfoundry.org/forum/?fromgroups#!forum/vcap-dev)
* Docs: [docs/](https://github.com/cloudfoundry/uaa/tree/master/docs)

## Quick Start

If this works you are in business:

    $ git clone git://github.com/cloudfoundry/uaa.git
    $ cd uaa
    $ mvn install

Each module has a `mvn tomcat:run` target to run individually, or you
could import them as projects into STS (use 2.8.0 or better if you
can).  The apps all work together the apps running on the same port
(8080) as `/uaa`, `/app` and `/api`.

You will need Maven 3.0.4 or newer.

### Deploy to Cloud Foundry

You can also build the app and push it to Cloud Foundry, e.g.

    $ mvn package install
    $ vmc push myuaa --path uaa/target

(If you do that, choose a unique application id, not 'myuaa'.)

### Demo of command line usage on local server

First run the UAA server as described above:

    $ cd uaa
    $ mvn tomcat:run

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
client like VMC. The token is stored in `~/.uuac.yml`, so dig into
that file and pull out the access token for your `vmc` target (or use
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
      client_id: vmc

### Demo of command line usage on cloudfoundry.com

The same command line example should work against a UAA running on
cloudfoundry.com (except for the token decoding bit because you won't
have the client secret). In this case, there is no need to run a local
uaa server, so simply ask the external login endpoint to tell you
about the system:

    $ curl -H "Accept: application/json" uaa.cloudfoundry.com/login
    {
      "prompts":{"username":["text","Username"],
        "password":["password","Password"]
      }
    }
    
You can then try logging in with the UAA ruby gem.  Make sure you have ruby 1.9, then

    $ gem install cf-uaac
    $ uaac target uaa.cloudfoundry.com
    $ uaac token get [yourusername] [yourpassword]

(or leave out the username / password to be prompted).

This authenticates and obtains an access token from the server using the OAuth2 implicit
grant, the same as used by a client like VMC. 

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

### Using Maven with to test with postgresql or mysql

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

2. `gem` is a ruby gem (`cf-uaa-client`) for interacting with the UAA server

3. `api` (sample) is an OAuth2 resource service which returns a mock list of deployed apps

4. `app` (sample) is a user application that uses both of the above

5. `login` (sample) is an application that performs authentication for the UAA acting as a back end service

In CloudFoundry terms

* `uaa` provides an authentication service plus authorized delegation for
   back-end services and apps (by issuing OAuth2 access tokens).

* `api` is a service that provides resources that other applications may
  wish to access on behalf of the resource owner (the end user).

* `app` is a webapp that needs single sign on and access to the `api`
  service on behalf of users.

* `login` is where Cloud Foundry administrators set up their
  authentication sources, e.g. LDAP/AD, SAML, OpenID (Google etc.) or
  social. The cloudfoundry.com platform uses a different
  implementation of the
  [login server](https://github.com/cloudfoundry/login-server).

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
    not requiring user at some point), and then the photos are shown.

2. See the currently logged in user details, a bag of attributes
grabbed from the open id provider

        GET /app

## The Login Application

A user interface for authentication.  The UAA can also authenticate
user accounts, but only if it manages them itself, and it only
provides a basic UI.  The Login app can be branded and customized for
non-native authentication and for more complicate UI flows, like user
registration and password reset.

The login application is actually itself an OAuth2 endpoint provider,
but delegates those features to the UAA server.  Configuration for the
login application therefore consists of locating the UAA through its
OAuth2 endpoint URLs, and registering the login application itself as
a client of the UAA.  There is a `login.yml` for the UAA locations,
e.g. for a local `vcap` instance:

    uaa:
      url: http://uaa.vcap.me
      token:
        url: http://uaa.vcap.me/oauth/token
      login:
        url: http://uaa.vcap.me/login.do
        
and there is an environment variable (or Java System property),
`LOGIN_SECRET` for the client secret that the app uses when it
authenticates itself with the UAA.  The Login app is registered by
default in the UAA only if there are no active Spring profiles (so not
at all in `vcap`).  In the UAA you can find the registration in the
`oauth-clients.xml` config file.  Here's a summary:

    id: login
    secret: loginsecret
    authorized-grant-types: client_credentials
    authorities: ROLE_LOGIN
    resource-ids: oauth

### Use Cases

1. Authenticate

        GET /login
        
    The sample app presents a form login interface for the backend
    UAA, and also an OpenID widget so the user can authenticate using
    Google etc. credentials.
    
2. Approve OAuth2 token grant

        GET /oauth/authorize?client_id=app&response_type=code...
        
    Standard OAuth2 Authorization Endpoint.  Client credentials and
    all other features are handled by the UAA in the back end, and the
    login application is used to render the UI (see
    `access_confirmation.jsp`).

3. Obtain access token

        POST /oauth/token
        
    Standard OAuth2 Authorization Endpoint passed through to the UAA.

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
