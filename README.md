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
* API Documentation: [UAA-APIs.rst](https://github.com/cloudfoundry/uaa/tree/master/docs/UAA-APIs.rst)
* Specification: [The Oauth 2 Authorization Framework](http://tools.ietf.org/html/rfc6749)
* LDAP: [UAA LDAP Integration](https://github.com/cloudfoundry/uaa/tree/master/docs/UAA-LDAP.md)

## Quick Start

If this works you are in business:

    $ git clone git://github.com/cloudfoundry/uaa.git
    $ cd uaa
    $ ./gradlew run

The apps all work together with the apps running on the same port
(8080) as `/uaa`, `/app` and `/api`.

### Deploy to Cloud Foundry

You can also build the app and push it to Cloud Foundry, e.g.

    $ ./gradlew :cloudfoundry-identity-uaa:war
    $ cf push myuaa --no-start -m 512M -b https://github.com/cloudfoundry/java-buildpack#v2.4 -p uaa/build/libs/cloudfoundry-identity-uaa-2.3.0.war 
    $ cf set-env myuaa SPRING_PROFILES_ACTIVE default
    $ cf set-env myuaa UAA_URL http://myuaa.<domain>
    $ cf set-env myuaa LOGIN_URL http://myuaa.<domain>
    $ cf set-env myuaa SPRING_PROFILES_ACTIVE default
    $ cf start myuaa

In the steps above, replace:
  
* `myuaa` with a unique application name
* `1.8.0` with the appropriate version label from your build
* `<domain>` this is your app domain. We will be parsing this from the system environment in the future
* We have not tested our system on Apache Tomcat 8 and Java 8, so we pick a build pack that produces lower versions

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

### Running local system against default MySQL and PostgreSQL settings (and Flyway migration script information)

    $ ./gradlew -Dspring.profiles.active=default,mysql run

This command will assume that there is a MySQL database available with the default settings for access
and will respond to the following JDBC settings.

    driver = 'org.mariadb.jdbc.Driver'
    url = 'jdbc:mysql://localhost:3306/uaa'
    user = 'root'
    password = 'changeme'
    schemas = ['uaa']

In a similar fashion, should you execute the command

    $ ./gradlew -Dspring.profiles.active=default,postgresql run

It uses the settings defined as

    driver = 'org.postgresql.Driver'
    url = 'jdbc:postgresql:uaa'
    user = 'root'
    password = 'changeme'

These settings are duplicated in two places for the Gradle integration.
They are defined as defaults in the Spring XML configuration files and they are defined in the main
build.gradle file. The reason they are in the Gradle build file, is so that during Gradle always executes the flywayClean
task prior to launching the UAA application. If you wish to not clean the DB, you can define the variable

    -Dflyway.clean=false

as part of your command line. This disables the flywayClean task in the gradle script.
Another way to disable to the flywayClean is to not specify the spring profiles on the command line,
but set the profiles in the uaa.yml and login.yml files.

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
  
will run the integration tests against a uaa server running in a local
Apache Tomcat instance, so for example the service URL is set to `http://localhost:8080/uaa` (by
default).  
  
You can point the `CLOUD_FOUNDRY_CONFIG_PATH` to pick up a
`uaa.yml` where URLs can be changed
and (if appropriate) set the context root for running the
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

    $ CLOUD_FOUNDRY_CONFIG_PATH=/tmp ./gradlew test
    
The webapp looks for a Yaml file in the following locations
(later entries override earlier ones) when it starts up.

    classpath:uaa.yml
    file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml
    file:${UAA_CONFIG_FILE}
    ${UAA_CONFIG_URL}

### Using Gradle to test with postgresql or mysql

The default uaa unit tests (./gradlew test) use hsqldb.

To run the unit tests using postgresql:

    $ echo "spring_profiles: default,postgresql" > src/main/resources/uaa.yml 
    $ ./gradlew -Dspring.profiles.active=default,postgresql test integrationTest

To run the unit tests using mysql:

    $ echo "spring_profiles: default,mysql" > src/main/resources/uaa.yml 
    $ ./gradlew -Dspring.profiles.active=default,mysql test integrationTest


The database configuration for the common and scim modules is defaulted in 
the Spring XML configuration files. You can change them by configuring them in `uaa.yml`

## Inventory

There are actually several projects here, the main `uaa` server application and some samples:

0. `common` is a module containing a JAR with all the business logic.  It is used in
the webapps below.

1. `uaa` is the actual UAA server

2. `api` (sample) is an OAuth2 resource service which returns a mock list of deployed apps

3. `app` (sample) is a user application that uses both of the above

4. `scim` [SCIM](http://www.simplecloud.info/) user management module used by UAA

5. `login` This module represents the UI of the UAA. It is the code that was merged in from the former login-server project.

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
`./gradlew run` to run it directly from `uaa` directory in the source
tree. When running with gradle it listens on port 8080 and the URL is
`http://localhost:8080/uaa`

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
credentials directly to the `/oauth/authorize` endpoint (as described in
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

    spring_profiles: postgresql,default
    
To use PostgreSQL instead of HSQL:

     $ echo "spring_profiles: default,postgresql" > src/main/resources/uaa.yml 
     $ ./gradlew run


## The API Sample Application

Two sample applications are included with the UAA. The `/api` and `/app`

Run it using `./gradlew run` from the `uaa` root directory 
All three apps, `/uaa`, `/api` and `/app` get deployed 
simultaneously.

## The App Sample Application

This is a user interface app (primarily aimed at browsers) that uses
OpenId Connect for authentication (i.e. SSO) and OAuth2 for access
grants.  It authenticates with the Auth service, and then accesses
resources in the API service.  Run it with `./gradlew run` from the
`uaa` root directory.

The application can operate in multiple different profiles according
to the location (and presence) of the UAA server and the Login
application.  By default it will look for a UAA on
`localhost:8080/uaa`, but you can change this by setting an
environment variable (or System property) called `UAA_PROFILE`.  In
the application source code (`samples/app/src/main/resources`) you will find
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
  [forks of this repository](https://github.com/cloudfoundry/uaa). If you
  want to contribute code this way, please reference an existing issue
  if there is one as well covering the specific issue you are
  addressing.  Always submit pull requests to the "develop" branch.
* Watch for upcoming articles on Cloud Foundry by
  [subscribing](http://blog.cloudfoundry.org) to the cloudfoundry.org
  blog
