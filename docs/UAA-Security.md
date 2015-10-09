# UAA Security Features and Configuration

It is the responsibility of a Resource Server to extract information
about the user and client application from the access token and make
an access decision based on that information.  This guide will help
authors of resource Servers and maintainers of client and user account
data to understand the range of information available and the kinds of
decisions that can be taken.  The UAA itself is a Resource Server, so
the access decisions taken by the UAA are used as an example.

- [UAA Security Features and Configuration](#uaa-security-features-and-configuration)
	- [User Accounts](#user-accounts)
		- [Security Metadata](#security-metadata)
		- [Bootstrap](#bootstrap)
		- [Account lockout policy](#account-lockout-policy)
	- [OAuth Client Applications](#oauth-client-applications)
		- [Security Metadata](#security-metadata)
		- [Bootstrap](#bootstrap)
		- [Demo Environment](#demo-environment)
		- [VCAP Dev Setup](#vcap-dev-setup)
	- [Token Scope Rules](#token-scope-rules)
		- [User Tokens](#user-tokens)
		- [Client Tokens](#client-tokens)
	- [UAA Resources](#uaa-resources)
		- [Token Management](#token-management)
		- [Client Registration](#client-registration)
		- [Client Secret Mangagement](#client-secret-mangagement)
		- [Password Change](#password-change)
		- [User Account Management](#user-account-management)
		- [Username from ID Queries](#username-from-id-queries)
		- [User Profiles](#user-profiles)
		- [Groups & Membership Management](#groups--membership-management)
		- [Token Resources for Providers](#token-resources-for-providers)
		- [Management Information](#management-information)
		- [Login Prompts](#login-prompts)

## User Accounts

### Security Metadata

User accounts are either of type "user" or type "admin" (using the
SCIM `type` field from the core schema).  These translate into granted
authorities, `[uaa.user]` or `[uaa.admin,uaa.user]` respectively, for
the purposes of access decisions within the UAA (i.e. admin users also
have the user role).  Granted authorities are not directly visible to
Resource Servers, but they show up as scopes in the access tokens.

Resource Servers may choose to use this information as part of an
access decision, and this may be good enough for simple use cases
(e.g. users belong to a small number of relatively static roles), but
in general they will need to maintain their own acess decision data
since roles on UAA don't necessarily correspond to the same thing on a
Resource Server.

Support for SCIM groups is currently provided only through the
authorities attribute of the user object.  Resource Servers that are
also SCIM clients can modify this attribute themselves, but it might
be better (and safer) if the data don't change much to have an admin
user or client do the role assignments.  In any case it is recommended
that Resource Servers have sensible defaults for new users that have
not yet been assigned a role.

### Bootstrap

There are 2 distinct scenarios:

1. Demo or test with vanilla code and no special environment.  A UAA
service started with no active Spring profile will initialize a single
user account (marissa/koala).

2. A `vcap` environment: integration testing or in production.  If the
service starts with any active Spring profile by default it will not
touch the user database.  The SCIM endpoints can be used to provision
user accounts, once a client with the correct privileges has been
registered.

In either case additional user accounts and client registrations can
be bootstrapped at start up by providing some data in `uaa.yml`.
Example users:

    scim:
      users:
        - paul|wombat|paul@test.org|Paul|Smith|uaa.admin
        - stefan|wallaby|stefan@test.org|Stefan|Schmidt

The format for the user is
`username|password|email|first_name|last_name(|comma-separated-authorities)`.
Remember that authorities are represented as groups in SCIM.

### Account lockout policy

In its default configuration, the UAA does not lock accounts permanently
when a user repeatedly fails authentication. Instead it temporarily locks a
user out for a short period (5 minutes by default) after 5 failed logins
within the previous hour. The failure count is reset when a user
successfully authenticates.

## OAuth Client Applications

### Security Metadata

Client application meta data can be used by Resource Servers to make
an access decision, and by the Authorization Server (the UAA itself)
to decide whether to grant an access token.

Scope values are arbitrary strings, but are a contract between a
client and a Resource Server, so in cases where UAA acts as a Resource
Server there are some "standard" values (`scim.read`, `scim.write`,
`passsword.write`, `openid`, etc.) whose usage and meaning is
described below.  Scopes are used by the Authorization Server to deny
a token requested for a scope not on the list, and should be used by a
Resource Server to deny access to a resource if the token has
insufficient scope.

UAA client applications have the following meta data (some are
optional, but to prevent mistakes it is usually better to use a
default value):

* authorized-grant-types: a comma-separated list of OAuth2 grant
  types, as defined in the spec: choose from `client_credentials`,
  `password`, `implicit`, `refresh_token`, `authorization_code`.  Used
  by the Authorization Server to deny a token grant if it is not on
  the list.  If in doubt use `authorization_code` and `refresh_token`.
* scope: a list of permitted scopes for this client to obtain on
  behalf of a user (so not relevant to `client_credentials` grants).
  Also used as the default scopes for a token where the client does
  not explicitly specify scopes in the authorization request.
* authorities: a list of granted authorities for the client
  (e.g. `uaa.admin` or any valid scope value).  The authorities are
  used to define the default scopes that are assigned to a token in a
  `client_credentials` grant, and to limit the legal values if
  explicit scopes are requested in that case.
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
to `uaa.yml`.  The UAA always starts with a registered `admin` client.
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
Cloud Foundry use cases (`cf` and `cloud_controller`).  If the `vcap`
Spring profile is active in the integration tests, no additional
accounts will be created.

Clients are bootstrapped from config if they are not present in the
backend when the system starts up (i.e. once the system has started up
once config changes will not affect the client registrations for
existing clients).  Certain fields (e.g. secret) can be reset if the
bootstrap component is configured to do so (it is not by default).

The `admin` client has the following properties (in the default
`uaa.yml` always present on the classpath but overriddable by
specifying all the values again in a custom config file):

      id: admin
      secret: adminsecret
      authorized-grant-types: client_credentials
      scope: none
      authorities: uaa.admin,clients.read,clients.write,clients.secret

The admin client can be used to bootstrap the system by adding
additional clients.  In particular, user accounts cannot be
provisioned until a client with access to the `scim` resource is
added.

### Demo Environment

The default Spring profile initializes 3 clients in addition to the
`admin` client, e.g. if the server is started from the command line
after a fresh clone from github for demo purposes:

    cf:
      id: cf
      authorized-grant-types: implicit
      scope: cloud_controller.read,cloud_controller.write,openid,password.write
      authorities: uaa.none
      resource-ids: none
    app:
      id: app
      secret: appclientsecret
      authorized-grant-types: password,authorization_code,refresh_token
      scope: cloud_controller.read,cloud_controller.write,openid,password.write,tokens.read,tokens.write
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
    cf:
      id: cf
      authorized-grant-types: implicit
      scope: cloud_controller.read,cloud_controller.write,openid,password.write
      authorities: uaa.none
      resource-ids: none
      redirect-uri: http://uaa.cloudfoundry.com/redirect/cf

The cloud controller secret is generated during the setup.  The same
clients are initialized in CF.com, but the secret is different.
Additional clients can be added during start up using `uaa.yml`, e.g.

    oauth:
      clients:
        cf:
          authorized-grant-types: implicit
          scope: cloud_controller.read,cloud_controller.write,password.write,openid
          authorities: uaa.none
          id: cf
          resource-ids: none
          redirect-uri: http://uaa.cloudfoundry.com/redirect/cf

## Token Scope Rules

When a client application asks for a new access token it can
optionally provide a set of requested scopes (space separated,
e.g. `scope=openid cloud_controller.read`).  The UAA will use that set
if provided and that will be the scope of the token if
granted. Otherwise, if no explicit value is requested, defaults will
be supplied according to what the client and user are allowed to do.
The rules governing the defaults and what is allowed are described
next.

### User Tokens

A token granted on behalf of a user (grant type anything except
`client_credentials`) takes its default scopes from the `scope` field
of the client registration.  Whether or not the default values are
used, the requested scopes are then validated:

* The user's authorities (SCIM groups) are augmented with some static
values, configurable but defaulting to
`[openid, cloud_controller.read, cloud_controller.write]`
* Allowed scopes consist of the intersection of the client scope and
the augmented user authorities.
* Disallowed scopes are removed from the request.
* If all the requested scopes are disallowed then clients get a 400
response with a JSON error message indicating the allowed values (for
implicit grants it should be a 302 according to the OAuth2 spec, but
that change hasn't been implemented yet).  The exception to that rule
is for clients with no registered scopes (no error in that case), but
there shouldn't be any such clients in a production system.

Note that the filtering of scopes by user authorities might mean that
a client gets a narrower-scoped token than it originally asked for,
e.g. if it asks for no `scope=dash.admin dash.user openid`, the token
might come back with only `dash.user openid`.  Tokens are opaque to
client applications, so they have to be prepared for resource servers
to deny access to some resources based on the scope of the token when
it is presented.

### Client Tokens

A token issued on a `client_credentials` grant has default and allowed
scopes equal to the client authorities.  Requesting a disallowed scope
will result in a 400 reponse and an error message that indicates the
allowed scopes.  A client would normally take the default scopes when
acting on its own behalf - since no approval is necessary there is no
point narrowing the scope.

## UAA Resources

All OAuth2 protected resource have an id (as listed individually).
Any request whose token does not have a matching resource id (`aud`
field in decoded token) will be rejected. Resources that are not
OAuth2 protected resources do not have a resource id (e.g. those with
simple HTTP Basic authentication).

### Token Management

Resource ID = `tokens`.  Rules:

* Revoke user token:
  * Token has scope `uaa.admin`, or
  * If token represents user, user is authenticated and is the owner
    of the token to be revoked, and token has scope `tokens.write`
* List user tokens:
  * Token has scope `uaa.admin` or
  * If token represents user, user is authenticated and is the owner
    of the token to be read, and token has scope `tokens.read`
* Revoke client token:
  * Token has scope `uaa.admin` or
  * Token represents the client in the token to be revoked, and token
    has scope `tokens.write`
* List client tokens:
  * Token has scope `uaa.admin` or
  * Token represents the client in the token to be revoked, and token
    has scope `tokens.read`

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

* List or search users
  * Token with scope `scim.read` provides read/query access to ALL users in the UAA

* Delete, add user account
  * Token has scope `scim.write`

* Update existing user account
  * Token with scope `scim.write` lets you update ANY user's information in the UAA

In addition, a User Token obtained by a client with authorities `scim.me` (eg. token from authorization_code
or password grant flow) provides read/query/update access to that particular user's account.

### Username from ID Queries

Resource ID = `scim`.  Rules:

* Obtain username information via `/ids/Users`
* ``filter`` parameter must be supplied
* Only attributes `userName`, `origin` and `id` are returned (and can be queried on)
* Requires `scim.userids` scope

### User Profiles

Used for Single Sign On (OpenID Connect lite).  Resource ID = `openid`.  Rules:

* Obtain user profile data
  * Token has scope `openid`

### Groups & Membership Management

Resource ID = `scim`. Rules:

* List or Search groups
  * Token has scope `scim.read`

* Delete or Add groups
  * Token has scope `scim.write`

* Update group name or add/remove members
  * Token has either `scim.write` OR `groups.update`

In addition, a User Token obtained by a client with authorities `scim.me` (eg. token from authorization_code
or password grant flow) provides the following access:

* List or Search groups
  * Response contains the group(s) that lists the user as a `reader`.

* Update group name or add/remove members
  * The user is listed as a `writer` in the group being updated.

### Token Resources for Providers

The UAA uses HTTP Basic authentication for these resources, so they
are no OAuth2 protected resources, but to simplify the security data
client registrations are used, so only registered clients can access
them.  The caller must have a secret (so `cf` and other implicit
grant clients need not apply).

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
