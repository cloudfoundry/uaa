# UAA Security Features and Configuration

It is the responsibility of a Resource Server to extract information
about the user and client application from the access token and make
an access decision based on that information.  This guide will help
authors of resource Servers and maintainers of client and user account
data to understand the range of information available and the kinds of
decisions that can be taken.  The UAA itself is a Resource Server, so
the access decisions taken by the UAA are used as an example.

## User Accounts

### Security Metadata

User accounts are either of type "user" or type "admin" (using the
SCIM `type` field from the core schema).  These translate into Spring
Security granted authorities `[ROLE_USER]` or `[ROLE_ADMIN,ROLE_USER]`
for the purposes of access decisions within the UAA (i.e. admin users
also have the user role).  Granted authorities are available to
Resource Servers via the `/check_token` endpoint, or by decoding the
access token.

Resource Servers may choose to use this information as part of an
access decision, but in general they will need to maintain their own
granted authorities data (or similar) since admin roles on UAA don't
necessarily correspond to the same thing on a Resource Server.

Support for SCIM groups is not currently provided, but could be in
future, potentially allowing Resource Servers to use that information
to infer granted authorities for their own purposes.

### Bootstrap

There are 2 distinct scenarios:

1. Demo or test with vanilla code and no special environment.  A UAA
service started with no active Spring profile will initialize a single
user account (marissa/koala).

2. A `vcap` environment: integration testing or in production.  If the
service starts with any active Spring profile it will not touch the
user database.  The SCIM endpoints can be used to provision user
accounts, once a client with the correct privileges has been
registered.

## OAuth Client Applications

### Security Metadata

Client application meta data can be used by Resource Servers to make
an access decision, and by the Authorization Server (the UAA itself)
to decide whether to grant an access token.  UAA client applications
have the following meta data (all are optional):

* authorized-grant-types: a list of OAuth2 grant types.  Used by the Authorization Server to deny a token grant if it is not on the list
* scope: a list of permitted scopes for this client.  Used by the Authorization Server to deny a token requested for a scope not on the list.  Used by Resource Servers to deny access to a resource if a token has insufficient scope.
* authorities: a list of granted authorities for the client (standard Spring Security format, e.g. `ROLE_CLIENT,ROLE_ADMIN`).  Can be used by Resource Servers to restrict access by clients with insufficient authority.
* secret: the shared secret used to authenticate token grant requests and token decoding operations (not revealed to Resource Server).
* resource-ids: white list of resource ids to be included in the decoded tokens granted to this client.  Resource Servers should reject requests carrying tokens that do not include their own id.  The values are not used by the Authorization Server.

### Bootstrap

Client registration can be initialized by adding client details data
to `uua.yml`.  The UAA always starts with a registered `admin` client.
There are 2 typical scenarios for additional client registration
bootstraps:

1. Demo or test with vanilla code and no custom `uaa.yml`.  A UAA
service started with no active Spring profile will start with some
client registrations (used in samples to make the out-of-the box
experience for new users as convenient as possible).  More clients and
user accounts will be created by the integration tests.

2. A `vcap` environment: integration testing or in production.  By
default no clients are created if any Spring profile is active, but
client registrations can be configured in `uaa.yml` and in some
well-known situations clients this will happen.  In particular, the
`dev_setup` environment and the CF.com deployment job both start up
with additional client registrations that are needed by the basic
Cloud Foundry use cases (`vmc` and `cloud_controller`).  If the `vcap`
Spring profile is active in the integration tests, no additional
accounts will be created.

The `admin` client has the following properties (in the default
`uaa.yml` always present on the classpath):

      authorized-grant-types: client_credentials
      scope: read,write,password
      authorities: ROLE_CLIENT,ROLE_ADMIN
      id: admin
      secret: adminclientsecret
      resource-ids: clients

The admin client can be used to bootstrap the system by adding
additional clients (it can't really be used for much else in fact).
In particular, user accounts cannot be provisioned until a client with
access to the `scim` resource is added.

### Demo Environment

The default Spring profile initializes 3 clients in addition to the
`admin` client, e.g. if the server is started from the command line
after a fresh clone from github for demo purposes:

    vmc:
      id: vmc
      authorized-grant-types: implicit
      scope: read,write,openid,password
      authorities: ROLE_UNTRUSTED
      resource-ids: password,cloud_controller
    app:
      id: app
      secret: appclientsecret
      authorized-grant-types: password,authorization_code,refresh_token
      scope: read,openid
      authorities: ROLE_CLIENT

### VCAP Dev Setup

In `dev_setup` these client accounts (in addition to the `admin`
client) are initialized:

    cloud_controller:
      authorized-grant-types: client_credentials
      scope: read,write,password
      authorities: ROLE_CLIENT,ROLE_ADMIN
      id: cloud_controller
      secret: ...
      resource-ids: scim,password,tokens
    vmc:
      authorized-grant-types: implicit
      scope: read,password
      authorities: ROLE_UNTRUSTED
      id: vmc
      resource-ids: cloud_controller,openid,password
      redirect-uri: http://uaa.cloudfoundry.com/redirect/vmc

The cloud controller secret is generated during the setup.  The same
clients are initialized in CF.com, but the secret is different.

## UAA Resources

All OAuth2 protected resource have an id (as listed individually).
Any request whose token does not have a matching resource id will be
rejected. Resources that are not OAuth2 protected resources do not
have a resource id (e.g. those with simple HTTP Basic authentication).

### Token Management

Resource ID = `tokens`.  Rules:

* Revoke user token: 
  * Client has `ROLE_ADMIN`
  * If token represents user, user has `ROLE_USER`
  * Token has scope `write`
* List user tokens:
  * Client has `ROLE_ADMIN`
  * If token represents user, user has `ROLE_USER`
  * Token has scope `read`
* Revoke client token:
  * Client has `ROLE_CLIENT`
  * Token does not represent user
  * Token has scope `write`
* List client tokens:
  * Client has `ROLE_CLIENT`
  * Token does not represent user
  * Token has scope `read`

### Client Registration

Resource ID = `clients`.  Rules:

* Remove, update or add client registration
  * Client has `ROLE_ADMIN`
  * If token represents user, user has `ROLE_ADMIN`
  * Token has scope `write`
* Inspect client registration
  * Client has `ROLE_ADMIN`
  * If token represents user, user has `ROLE_ADMIN`
  * Token has scope `read`

### Password Change

Resource ID = `password`.  Rules:

* Change password
  * Token has scope `password`
  * If token represents a client, it has `ROLE_ADMIN`
  * If token represents a user, either he has `ROLE_ADMIN` or he provides the old password
  
### User Account Management

Resource ID = `scim`.  Rules:

* List or inspect users
  * Client has `ROLE_CLIENT`
  * Token has scope `read`

* Delete, add or update user account
  * Client has `ROLE_CLIENT`
  * Token has scope `write`

### User Profiles

Used for Single Sign On (OpenID Connect lite).  Resource ID = `openid`.  Rules:

* Obtain user profile data
  * Token has scope `openid`
  
### Token Client Resources

The UAA uses HTTP Basic authentication for these resources.  In all
cases the client must have a secret (so `vmc` and other implicit grant
clients need not apply).

* Obtain access token
  * Client is authenticated
  
* Inspect access token
  * Client is authenticated
  * Client has `ROLE_CLIENT`
  
* Obtain token key (for decoding JWT tokens locally)
  * Client is authenticated
  * Client has `ROLE_CLIENT`
  
* Change token key
  * Client is authenticated
  * Client has `ROLE_ADMIN`

### Management Information

The `/varz` endpoint is protected by HTTP Basic authentication with
credentials that are externalized via `uaa.yml`.  They have defaults
(`varz:varzclientsecret`) and can also be overridden via System
properties.

### Login Prompts

The login endpoint is unsecured.  Any client can ask it and it will
respond with some information about the system and the login prompts
required to authenticate.
