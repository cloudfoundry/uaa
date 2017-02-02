<link href="https://raw.github.com/clownfart/Markdown-CSS/master/markdown.css" rel="stylesheet"></link>
# CloudFoundry User Account and Authentication (UAA) Server

[![Build Status](https://travis-ci.org/cloudfoundry/uaa.svg?branch=develop)](https://travis-ci.org/cloudfoundry/uaa)
[![Coverage Status](https://coveralls.io/repos/cloudfoundry/uaa/badge.png?branch=develop)](https://coveralls.io/r/cloudfoundry/uaa?branch=develop)

The UAA is a multi tenant identity management service, used in Cloud Foundry, but also available
as a stand alone OAuth2 server.  It's primary role is as an OAuth2 provider, issuing tokens for client
applications to use when they act on behalf of Cloud Foundry users.
It can also authenticate users with their Cloud Foundry credentials,
and can act as an SSO service using those credentials (or others).  It
has endpoints for managing user accounts and for registering OAuth2
clients, as well as various other management functions.

## Co-ordinates

* Tokens: [A note on tokens, scopes and authorities](/docs/UAA-Tokens.md)
* Technical forum: [cf-dev mailing list](https://lists.cloudfoundry.org)
* Docs: [docs/](/docs)
* API Documentation: http://docs.cloudfoundry.org/api/uaa/
* Specification: [The Oauth 2 Authorization Framework](http://tools.ietf.org/html/rfc6749)
* LDAP: [UAA LDAP Integration](/docs/UAA-LDAP.md)

## Quick Start

Requirements:
* Java 8

If this works you are in business:

    $ git clone git://github.com/cloudfoundry/uaa.git
    $ cd uaa
    $ ./gradlew  run
    
    
NOTE: Recent changes removed default keys and default users from the UAA.
We currently enable default keys using the LOGIN_CONFIG_URL variable and load
default sample data is loaded using the `default` spring profile (`spring.profiles.active`).
In the gradle script we set `LOGIN_CONFIG_URL=file://$PWD/uaa/src/main/resources/required_configuration.yml`

The apps all work together with the apps running on the same port
(8080) as [`/uaa`](http://localhost:8080/uaa), [`/app`](http://localhost:8080/app) and [`/api`](http://localhost:8080/api).

UAA will log to a file called `uaa.log` which can be found using the following command:-

    $ sudo find / -name uaa.log

which you should find under something like:-

    /private/var/folders/7v/518b18d97_3f4c8fzxphy6f8zcm51c/T/cargo/conf/logs/

### Deploy to Cloud Foundry

Currently you are also required to set the following values that are not included with the defaults:
https://github.com/cloudfoundry/uaa/blob/master/uaa/src/main/resources/required_configuration.yml


You can also build the app and push it to Cloud Foundry, e.g.
Our recommended way is to use a manifest file, but you can do everything on the command line.

Assuming we have a [local bosh-lite](https://github.com/cloudfoundry/bosh-lite) instance running you could do

    $ ./gradlew manifests
    $ cf api --skip-ssl-validation api.bosh-lite.com
    $ cf auth admin admin
    $ cf create-org sample-org
    $ cf create-space -o sample-org sample-space
    $ cf target -o sample-org -s sample-space
    $ cf push -f build/sample-manifests/uaa-cf-application.yml

Your application is now available on [http://myuaa.bosh-lite.com](http://myuaa.bosh-lite.com)

We can also deploy to Pivotal Web Services

    $ ./gradlew manifests -Dapp=myuaa-app -Dapp-domain=cfapps.io
    $ cf api api.run.pivotal.io
    $ cf auth <your username> <your password>
    $ cf create-org <your org>
    $ cf create-space -o <your org> <your space>
    $ cf target -o <your org> -s <your space>
    $ cf push -f build/sample-manifests/uaa-cf-application.yml

### Demo of command line usage on local server

First run the UAA server as described above:

    $ ./gradlew run

From another terminal you can use curl to verify that UAA has started by
requesting system information:

    $ curl -H "Accept: application/json" localhost:8080/uaa/login
    {
      "timestamp":"2012-03-28T18:25:49+0100",
      "commit_id":"111274e",
      "prompts":{"username":["text","Username"],
        "password":["password","Password"]
      }
    }

For complex requests it is more convenient to interact with UAA using 
`uaac`, the [UAA Command Line Client](https://github.com/cloudfoundry/cf-uaac). 
If you have a recent ruby installed, install the CLI and use it to 
obtain an access token:

    $ gem install cf-uaac
    $ uaac target http://localhost:8080/uaa
    $ uaac token get marissa koala

If you omit the username or password the CLI will prompt you for those
fields.

This authenticates and obtains an access token from the server using
the OAuth2 implicit grant, similar to the approach intended for a
client like CF. The token is stored in `~/.uaac.yml`, so dig into
that file and pull out the access token for your `cf` target (or use
`--verbose` on the login command line above to see it logged to your
console).

Then you can login as a resource server and retrieve the token
details:

    $ uaac target http://localhost:8080/uaa
    $ uaac token decode
    
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

    $ cat > /tmp/config/uaa.yml
    uaa:
      host: uaa.appcloud21.dev.mozycloud
      test:
        username: dev@cloudfoundry.org # defaults to vcap_tester@vmware.com
        password: changeme
        email: dev@cloudfoundry.org

then from `uaa/uaa`

    $ CLOUD_FOUNDRY_CONFIG_PATH=/tmp/config ./gradlew test
    
The webapp looks for Yaml content in the following locations
(later entries override earlier ones) when it starts up.

    classpath:uaa.yml
    file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml
    file:${UAA_CONFIG_FILE}
    ${UAA_CONFIG_URL}
    System.getEnv('UAA_CONFIG_YAML') -> environment variable, if set must contain valid Yaml

For example, to deploy the UAA as a Cloud Foundry application, you can provide an application manifest like

    ---
      applications:
      - name: standalone-uaa-cf-war
        memory: 1024M
        instances: 1
        host: standalone-uaa
        path: cloudfoundry-identity-uaa-<YOUR-VERSION-HERE>.war
        env:
          JBP_CONFIG_SPRING_AUTO_RECONFIGURATION: '[enabled: false]'
          JBP_CONFIG_TOMCAT: '{tomcat: { version: 7.0.+ }}'
          SPRING_PROFILES_ACTIVE: hsqldb,default
          UAA_CONFIG_YAML: |
            uaa.url: http://standalone-uaa.cfapps.io
            login.url: http://standalone-uaa.cfapps.io
            smtp:
              host: mail.server.host
              port: 3535


Or as an alternative, set the yaml configuration as a string for an environment variable using the set-env command

    cf set-env sample-uaa-cf-war UAA_CONFIG_YAML '{ uaa.url: http://standalone-uaa.myapp.com, login.url: http://standalone-uaa.myapp.com, smtp: { host: mail.server.host, port: 3535 } }'
    
In addition, any simple type property that is read by the UAA can also be fully expanded and read as a system environment variable itself.
Notice how uaa.url can be converted into an environment variable called UAA_URL

    ---
      applications:
      - name: standalone-uaa-cf-war
        memory: 1024M
        instances: 1
        host: standalone-uaa
        path: cloudfoundry-identity-uaa-<YOUR-VERSION-HERE>.war
        env:
          JBP_CONFIG_SPRING_AUTO_RECONFIGURATION: '[enabled: false]'
          JBP_CONFIG_TOMCAT: '{tomcat: { version: 7.0.+ }}'
          SPRING_PROFILES_ACTIVE: hsqldb,default
          UAA_URL: http://standalone-uaa.cfapps.io
          LOGIN_URL: http://standalone-uaa.cfapps.io
          UAA_CONFIG_YAML: |
            smtp:
              host: mail.server.host
              port: 3535

### Using Gradle to test with postgresql or mysql

The default uaa unit tests (./gradlew test integrationTest) use hsqldb.

To run the unit tests using postgresql:

    $ ./gradlew -Dspring.profiles.active=default,postgresql test integrationTest

Optionally, the Spring profile can be configured in the `uaa.yml` file
 
    $ echo "spring_profiles: default,postgresql" > src/main/resources/uaa.yml

To run the unit tests using mysql:

    $ ./gradlew -Dspring.profiles.active=default,mysql test integrationTest


The database configuration for the common and scim modules is defaulted in 
the [Spring XML configuration files](https://github.com/cloudfoundry/uaa/blob/master/common/src/main/resources/spring/env.xml). 
You can change them by configuring them in `uaa.yml`

The defaults are

    PostgreSQL: User: root Password: changeme Database: uaa Host: localhost Port: 5432
    MySQL:      User: root Password: changeme Database: uaa Host: localhost Port: 3306

## Inventory

There are actually several projects here, the main `uaa` server application, a client library and some samples:

1. `uaa` a WAR project for easy deployment

2. `server` a JAR project containing the implementation of UAA's REST API (including [SCIM](http://www.simplecloud.info/)) and UI 

3. `model` a JAR project used by both the client library and server 

4. `client-lib` a JAR project that provides a Java client API

5. `api` (sample) is an OAuth2 resource service which returns a mock list of deployed apps

6. `app` (sample) is a user application that uses both of the above

In CloudFoundry terms

* `uaa` provides an authentication service plus authorized delegation for
   back-end services and apps (by issuing OAuth2 access tokens).

* `api` is a service that provides resources that other applications may
  wish to access on behalf of the resource owner (the end user).

* `app` is a webapp that needs single sign on and access to the `api`
  service on behalf of users.

### Organization of Code

The projects are organized into horizontal layers; client, model, server, etc.  Within all of these projects the java packages are organized vertically around our internal services; zones, providers, clients, etc. 


## UAA Server

The authentication service is `uaa`. It's a plain Spring MVC webapp.
Deploy as normal in Tomcat or your container of choice, or execute
`./gradlew run` to run it directly from `uaa` directory in the source
tree. When running with gradle it listens on port 8080 and the URL is
`http://localhost:8080/uaa`

The UAA Server supports the APIs defined in the UAA-APIs document. To summarise:

1. The OAuth2 /oauth/authorize and /oauth/token endpoints

2. A /login_info endpoint to allow querying for required login prompts

3. A /check_token endpoint, to allow resource servers to obtain information about
an access token submitted by an OAuth2 client.

4. A /token_key endpoint, to allow resource servers to obtain the verification key to verify token signatures

5. SCIM user provisioning endpoint

6. OpenID connect endpoints to support authentication /userinfo. Partial OpenID support.

Authentication can be performed by command line clients by submitting
credentials directly to the `/oauth/authorize` endpoint (as described in
UAA-API doc).  There is an `ImplicitAccessTokenProvider` in Spring
Security OAuth that can do the heavy lifting if your client is Java.

By default `uaa` will launch with a context root `/uaa`. 

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

There are two configuration files, `uaa.yml` and `login.yml`, in the application which provides defaults to the
placeholders in the Spring XML.   
Wherever you see `${placeholder.name}` in the XML there is an opportunity to override
it either by providing a System property (`-D` to JVM) with the same
name, or a custom `uaa.yml` or `login.yml` (as described above).

The `uaa.yml` and `login.yml` get merged during startup into one configuration.

All passwords and client secrets in the config files are plain text,
but they will be inserted into the UAA database encrypted with BCrypt.

In the future, you will be able to provide passwords in bcrypt format to avoid having to specify clear text passwords.

### User Account Data

The default is to use an in-memory RDBMS user store that is
pre-populated with a single test users: `marissa` has password
`koala`.

To use Postgresql for user data, activate the Spring profile `postgresql`.

The active profiles can be configured in `uaa.yml` using

    spring_profiles: postgresql,default
    
Or specify PostgreSQL on the command line:

     $ ./gradlew -Dspring.profiles.active=default,postgresql run
     
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

* The UAA has two requirements
  * JDK 1.8.0
  * PhantomJS, for integration test, [http://phantomjs.org/download.html](http://phantomjs.org/download.html)
* Get involved with the Cloud Foundry community on the mailing lists.
  Please help out on the
  [mailing list](https://lists.cloudfoundry.org)
  by responding to questions and joining the debate.
* Create [github](https://github.com/cloudfoundry/uaa/issues) tickets for bugs and new features and comment and
  vote on the ones that you are interested in.
* Github is for social coding: if you want to write code, we encourage
  contributions through pull requests from
  [forks of this repository](https://github.com/cloudfoundry/uaa). If you
  want to contribute code this way, please reference an existing issue
  if there is one as well covering the specific issue you are
  addressing.  Always submit pull requests to the "develop" branch.
  We strictly adhere to test driven development. We kindly ask that 
  pull requests are accompanied with test cases that would be failing
  if ran separately from the pull request.
* Watch for upcoming articles on Cloud Foundry by
  [subscribing](http://blog.cloudfoundry.org) to the cloudfoundry.org
  blog


## Acknowledgements

* YourKit supports open source projects with its full-featured Java Profiler.
  YourKit, LLC is the creator of <a href="https://www.yourkit.com/java/profiler/index.jsp">YourKit Java Profiler</a>
  and <a href="https://www.yourkit.com/.net/profiler/index.jsp">YourKit .NET Profiler</a>,
  innovative and intelligent tools for profiling Java and .NET applications.
  [![](https://www.yourkit.com/images/yklogo.png)](https://www.yourkit.com/java/profiler/index.jsp)
