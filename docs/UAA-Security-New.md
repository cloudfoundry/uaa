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
SCIM `type` field from the core schema).  These translate into granted
authorities, `[uaa.user]` or `[uaa.admin,uaa.user]` respectively,
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

* authorized-grant-types: a comman separated list of OAuth2 grant
  types, as defined in the spec: choose from `client_credentials`,
  `password`, `implicit`, `refresh_token`, `authorization_code`.  Used
  by the Authorization Server to deny a token grant if it is not on
  the list
* scope: a list of permitted scopes for this client to obtain on
  behalf of a user (no not relevant to `client_credentials` grants).
  The values are arbitrary strings, but are a contract between a
  client and a Resource Server, so in cases where UAA acts as a
  Resource Server there are some "standard" values (`scim.read`,
  `scim.write`, `passsword.write`, `openid`, etc.) whose usage and
  meaning is described below.  Scopes are used by the Authorization
  Server to deny a token requested for a scope not on the list.  They
  can and should be used by Resource Servers to deny access to a
  resource if a token has insufficient scope.
* authorities: a list of granted authorities for the client
  (e.g. `uaa.admin` or any valid scope value).  The authorities are
  used to limit the scopes that can be assigned to a token in a
  `client_credentials` grant.
* secret: the shared secret used to authenticate token grant requests
  and token decoding operations (not revealed to Resource Server).
* resource-ids: white list of resource ids to be included in the
  decoded tokens granted to this client.  The UAA does not store any
  data here (it should be `none` for all clients), but instead creates
  a list of resource ids dynamically from the scope values when a
  token is granted.  The resource id is extracted from a scope using a
  period separator (the last occurrence in the string) except for some
  standard values (e.g. `openid`) that are not controlled by the UAA
  or its own resources.  So a scope of `cloud_controller.read` is
  assigned a resource id of `cloud_controller`, for instance.

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

Clients are bootstrapped from config if they are not present in the
backend when the system starts up (i.e. once the system has started up
once config changes will not affect the client registrations for
existing clients).

The `admin` client has the following properties (in the default
`uaa.yml` always present on the classpath but overriddable by
specifying all the values again in a custom config file):

      authorized-grant-types: client_credentials
      scope: none
      authorities: uaa.admin,clients.read,clients.write,clients.secret
      id: admin
      secret: adminclientsecret

The admin client can be used to bootstrap the system by adding
additional clients (the intention is that it can't really be used for
much else in fact).  In particular, user accounts cannot be
provisioned until a client with access to the `scim` resource is
added.

### Demo Environment

The default Spring profile initializes 3 clients in addition to the
`admin` client, e.g. if the server is started from the command line
after a fresh clone from github for demo purposes:

    vmc:
      id: vmc
      authorized-grant-types: implicit
      scope: cloud_controller.read,cloud_controller.write,openid,password.write
      authorities: uaa.none
      resource-ids: none
    app:
      id: app
      secret: appclientsecret
      authorized-grant-types: password,authorization_code,refresh_token
      scope: cloud_controller.read,openid
      authorities: uaa.none
      resource-ids: none

### VCAP Dev Setup

In `dev_setup` these client accounts (in addition to the `admin`
client) are initialized:

    cloud_controller:
      authorized-grant-types: client_credentials
      scope: none
      authorities: scim.read,scim.write,password.write,tokens.read,tokens.write
      id: cloud_controller
      secret: ...
      resource-ids: none
    vmc:
      id: vmc
      authorized-grant-types: implicit
      scope: cloud_controller.read,cloud_controller.write,openid,password.write
      authorities: uaa.none
      resource-ids: none
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
  * If token represents a client, it has scope `uaa.admin`
  * If token represents user, user is authenticated and is the owner of the token to be revoked
  * Token has scope `tokens.write`
* List user tokens:
  * If token represents a client, it has scope `uaa.admin`
  * If token represents user, user is authenticated and is the owner of the token to be read
  * Token has scope `tokens.read`
* Revoke client token:
  * Token has scope `uaa.admin` or represents the client in the token to be revoked
  * Token has scope `tokens.write`
* List client tokens:
  * Token has scope `uaa.admin` or represents the client in the token to be revoked
  * Token has scope `tokens.read`

### Client Registration

Resource ID = `clients`.  Rules:

* Remove, update or add client registration
  * Token has scope `clients.write`
* Inspect client registration
  * Token has scope `clients.read`
  
### Client Secret Mangagement

Resource ID null (so all clients can change their password).  Rule:

* Change secret
  * Token has scope `clients.secret`
  * Either token has scope `uaa.admin` or client can only change its own secret
  * Either token has scope `uaa.admin` or client provides the old secret
  * Even if token has scope `uaa.admin` client must provide the old value to change its own secret

### Password Change

Resource ID = `password`.  Rules:

* Change password
  * Token has scope `password.write`
  * If token represents a client, scope includes `uaa.admin`
  * If token represents a user, either scope includes `uaa.admin` or user provides the old password
  
### User Account Management

Resource ID = `scim`.  Rules:

* List or inspect users
  * Token has scope `scim.read`

* Delete, add or update user account
  * Token has scope `scim.write`

### User Profiles

Used for Single Sign On (OpenID Connect lite).  Resource ID = `openid`.  Rules:

* Obtain user profile data
  * Token has scope `openid`
  
### Token Client Resources

The UAA uses HTTP Basic authentication for these resources, so they
are no OAuth2 protected resources.  In all cases the client must have
a secret (so `vmc` and other implicit grant clients need not apply).

* Obtain access token at `/oauth/token`
  * Client is authenticated
  * If grant type is `authorization_code` client must have the code
  
* Inspect access token at `/check_token`
  * Client is authenticated
  * Client has authority `uaa.resource`
  
* Obtain token key (for decoding JWT tokens locally) at `/token_key`
  * Client is authenticated
  * Client has authority `uaa.resource`
  
### Management Information

The `/varz` endpoint is protected by HTTP Basic authentication with
credentials that are externalized via `uaa.yml`.  They have defaults
(`varz:varzclientsecret`) and can also be overridden via System
properties.

### Login Prompts

The login endpoint is unsecured.  Any client can ask it and it will
respond with some information about the system and the login prompts
required to authenticate.
