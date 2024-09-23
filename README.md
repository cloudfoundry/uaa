<link href="https://raw.github.com/clownfart/Markdown-CSS/master/markdown.css" rel="stylesheet"></link>

**Slack** [&#35;uaa](https://cloudfoundry.slack.com/archives/C03FXANBV)

# CloudFoundry User Account and Authentication (UAA) Server, test

The UAA is a multi tenant identity management service, used in Cloud Foundry, but also available
as a stand alone OAuth2 server.  Its primary role is as an OAuth2 provider, issuing tokens for client
applications to use when they act on behalf of Cloud Foundry users.
It can also authenticate users with their Cloud Foundry credentials,
and can act as an SSO service using those credentials (or others).  It
has endpoints for managing user accounts and for registering OAuth2
clients, as well as various other management functions.

[![](https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm-300x157.png)](https://openid.net/certification/)

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

## Co-ordinates

* Tokens: [A note on tokens, scopes and authorities](/docs/UAA-Tokens.md)
* Technical forum: [cf-dev mailing list](https://lists.cloudfoundry.org)
* Docs: [docs/](/docs)
* API Documentation: http://docs.cloudfoundry.org/api/uaa/
* Specification: [The OpenID Connect Core Framework](https://openid.net/specs/openid-connect-core-1_0.html) including [the Oauth 2 Authorization Framework](http://tools.ietf.org/html/rfc6749)
* LDAP: [UAA LDAP Integration](/docs/UAA-LDAP.md)

## Quick Start

Requirements:
* Java 17

If this works you are in business:

    $ git clone git://github.com/cloudfoundry/uaa.git
    $ cd uaa
    $ ./gradlew run


The apps all work together with the apps running on the same port
(8080) as [`/uaa`](http://localhost:8080/uaa), [`/app`](http://localhost:8080/app) and [`/api`](http://localhost:8080/api).

UAA will log to a file called `uaa.log` which can be found using the following command:-

    $ sudo lsof | grep uaa.log

which you should find under something like:-

    $TMPDIR/cargo/conf/logs/

### Demo of command line usage on local server

First run the UAA server as described above:

    $ ./gradlew run

From another terminal you can use curl to verify that UAA has started by
requesting system information:

    $ curl --silent --show-error --head localhost:8080/uaa/login | head -1
    HTTP/1.1 200

For complex requests it is more convenient to interact with UAA using
`uaac`, the [UAA Command Line Client](https://github.com/cloudfoundry/cf-uaac).

### Debugging local server

To load JDWP agent for UAA jvm debugging, start the server as follows:
```sh
./gradlew run -Dxdebug=true
```
or
```sh
./gradlew -Dspring.profiles.active=default,hsqldb,debug run
```
You can then attach your debugger to port 5005 of the jvm process.

To suspend the server start-up until the debugger is attached (useful for
debugging start-up code), start the server as follows:
```sh
./gradlew run -Dxdebugs=true
```
or
```sh
./gradlew -Dspring.profiles.active=default,hsqldb,debugs run
```

## Running local UAA server with different databases
`./gradlew run` runs the UAA server with hsqldb database by default.

### MySql
1. Start the mysql server (e.g. a mysql docker container)
```sh
% docker run --name mysql1 -e MYSQL_ROOT_PASSWORD=changeme -d -p3306:3306 mysql
```
2. Create the `uaa` database (e.g. in mysql interactive session)
```sh
% mysql -h 127.0.0.1 -u root -p
...
mysql> create database uaa;
```
3. Run the UAA server with the mysql profile
```sh
% ./gradlew -Dspring.profiles.active=mysql,default run
```

### PostgreSQL
1. Start the postgresql server (e.g. a postgres docker container)
```sh
docker run --name postgres1 -p 5432:5432 -e POSTGRES_PASSWORD=mysecretpassword -d postgres
```
2. Create the `uaa` database (e.g. in psql interactive session)
```sh
% psql -h 127.0.0.1 -U postgres
```
```postgresql
create database uaa;
create user root with superuser password 'changeme';
```
3. Run the UAA server with the postgresql profile
```sh
% ./gradlew -Dspring.profiles.active=postgresql,default run
```
4. Once the UAA server started, you can see the tables created in the uaa database (e.g. in psql interactive session)
```postgresql
\c uaa
psql (14.5 (Homebrew), server 15.0 (Debian 15.0-1.pgdg110+1))
WARNING: psql major version 14, server major version 15.
         Some psql features might not work.
You are now connected to database "uaa" as user "postgres".
\d
List of relations
 Schema |             Name              |   Type   | Owner
--------+-------------------------------+----------+-------
 public | authz_approvals               | table    | root
 public | expiring_code_store           | table    | root
 public | external_group_mapping        | table    | root
 public | external_group_mapping_id_seq | sequence | root
 public | group_membership              | table    | root
 public | group_membership_id_seq       | sequence | root
 public | groups                        | table    | root
 public | identity_provider             | table    | root
 public | identity_zone                 | table    | root
 public | oauth_client_details          | table    | root
 public | oauth_code                    | table    | root
 public | oauth_code_id_seq             | sequence | root
 public | revocable_tokens              | table    | root
 public | schema_version                | table    | root
 public | sec_audit                     | table    | root
 public | sec_audit_id_seq              | sequence | root
 public | spring_session                | table    | root
 public | spring_session_attributes     | table    | root
 public | user_info                     | table    | root
 public | users                         | table    | root
(23 rows)
```

## Running tests

You can run the integration tests with docker

    $ run-integration-tests.sh <dbtype>

will create a docker container running uaa + ldap + database whereby integration tests are run against.

### Using Gradle to test with postgresql or mysql

The default uaa unit tests (./gradlew test integrationTest) use hsqldb.

To run the unit tests with docker:

    $ run-unit-tests.sh <dbtype>

### To run a single test

The default uaa unit tests (`./gradlew test`) use hsqldb. 

Start by finding out which gradle project your test belongs to.
You can find all project by running

    $ ./gradlew projects

To run a specific test class, you can specify the module and the test class. 
    
    $ ./gradlew :<project name>:test --tests <TestClass>.<MethodName>

In this example, it's running only the 
JdbcScimGroupMembershipManagerTests tests in the cloudfoundry-identity-server module:

    $ ./gradlew :cloudfoundry-identity-server:test \
    --tests "org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManagerTests"

or to run all tests in a Class

    $ ./gradlew :<project name>:test --tests <TestClass>

You might want to use the full gradle command found at the bottom of
the `scripts/unit-tests.sh` script by prepending the project name to
the `test` command and adding the `--tests` option.

### Building war file

    $ ./gradlew :clean :assemble -Pversion=${UAA_VERSION}

## Inventory

There are actually several projects here, the main `uaa` server application, a client library and some samples:

1. `uaa` a WAR project for easy deployment

2. `server` a JAR project containing the implementation of UAA's REST API (including [SCIM](http://www.simplecloud.info/)) and UI

3. `model` a JAR project used by both the client library and server

4. `api` (sample) is an OAuth2 resource service which returns a mock list of deployed apps

5. `app` (sample) is a user application that uses both of the above

In CloudFoundry terms

* `uaa` provides an authentication service plus authorized delegation for
   back-end services and apps (by issuing OAuth2 access tokens).

* `api` is a service that provides resources that other applications may
  wish to access on behalf of the resource owner (the end user).

* `app` is a webapp that needs single sign on and access to the `api`
  service on behalf of users.

# Running the UAA on Kubernetes

__Prerequisites__
* [ytt](https://get-ytt.io/), tested with 0.24.0
* [kubectl](https://kubernetes.io/docs/reference/kubectl/overview/)

The Kubernetes deployment is in active development.  You should expect frequent (and possibly breaking) changes. This section will be updated as progress is made on this feature set. As of now:

The [K8s directory](./k8s) contains `ytt` templates that can be rendered and applied to a K8s cluster.

In development, [this Makefile](./k8s/Makefile) can be used for common rendering and deployment activities.

In production, you'll most likely want to use ytt directly. Something like this should get you going:

`$ ytt -f templates -f values/default-values.yml | kubectl apply -f -`

If you'd like to overide some of those values, you can do so by taking advantage of YTT's [overlay functionality](https://get-ytt.io/#example:example-multiple-data-values).

`$ ytt -f templates -f values/default-values.yml -f your-dir/production-values.yml | kubectl apply -f -`

Of course, you can always abandon the default values altogether and provide your own values file.

# Contributing to the UAA

Here are some ways for you to get involved in the community:

* Join uaa on slack [&#35;uaa](https://cloudfoundry.slack.com/archives/C03FXANBV)
* Create [github](https://github.com/cloudfoundry/uaa/issues) tickets for bugs and new features and comment and
  vote on the ones that you are interested in.
* Github is for social coding: if you want to write code, we encourage
  contributions through pull requests from
  [forks of this repository](https://github.com/cloudfoundry/uaa). If you
  want to contribute code this way, please reference an existing issue
  if there is one as well covering the specific issue you are
  addressing. Always submit pull requests to the "develop" branch.
  We strictly adhere to test driven development. We kindly ask that
  pull requests are accompanied with test cases that would be failing
  if ran separately from the pull request.
* After you create the pull request, you can check the code metrics yourself  
  in [Github Actions](https://github.com/cloudfoundry/uaa/actions) and on [Sonar](https://sonarcloud.io/project/pull_requests_list?id=cloudfoundry-identity-parent). 
  The goal for new code should be close to 100% tested and clean code: 
  [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=cloudfoundry-identity-parent&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=cloudfoundry-identity-parent)

# Connecting UAA to local LDAP Server

Requirements:
* [Docker](https://docs.docker.com/engine/reference/commandline/cli/)
* [Docker Compose](https://docs.docker.com/compose/reference/)

To debug UAA and LDAP integrations, we use an OpenLdap docker image from [VMWare's Bitnami project](https://github.com/bitnami/bitnami-docker-openldap)

1. Modify file `uaa/src/main/resources/uaa.yml` and enable LDAP by uncommenting line 7, `spring_profiles: ldap,default,hsqldb`
1. run `docker-compose up` from directory `scripts/ldap`
2. From `scripts/ldap` verify connectivity to running OpenLdap container by running `docker-confirm-ldapquery.sh`
3. Start UAA with `./gradlew run`
4. Navigate to [`/uaa`](http://localhost:8080/uaa) and log in with LDAP user `user01` and password `password1`

Use below command to clean-up container and volume:
- `docker-compose down --volumes`
