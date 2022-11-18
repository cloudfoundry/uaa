<link href="https://raw.github.com/clownfart/Markdown-CSS/master/markdown.css" rel="stylesheet"></link>

# CloudFoundry User Account and Authentication (UAA) Server

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
* Specification: [The Oauth 2 Authorization Framework](http://tools.ietf.org/html/rfc6749)
* LDAP: [UAA LDAP Integration](/docs/UAA-LDAP.md)

## Quick Start

Requirements:
* Java 11

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
You can then attach your debugger to port 5005 of the jvm process.

## Running tests

You can run the integration tests with docker

    $ run-integration-tests.sh <dbtype>
  
will create a docker container running uaa + ldap + database whereby integration tests are run against.


To run the unit tests with docker:

    $ run-unit-tests.sh <dbtype>

### Running specific unit tests

The default uaa unit tests (`./gradlew test`) use hsqldb. 

To run a specific test class, you can specify the module and the test class. In this example, it's running only the 
JdbcScimGroupMembershipManagerTests tests in the cloudfoundry-identity-server module:

    $ ./gradlew :cloudfoundry-identity-server:test \
    --tests "org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManagerTests"

## Building war file

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

## Connecting UAA to local LDAP Server

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
