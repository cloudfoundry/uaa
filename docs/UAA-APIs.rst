============================================
User Account and Authentication Service APIs
============================================

.. contents:: Table of Contents

Overview
========

The User Account and Authentication Service (UAA):

* is a separate application from Cloud Foundry the Cloud Controller
* owns the user accounts and authentication sources (SAML, OpenID Connect, LDAP, Keystone)
* is invoked via JSON APIs
* supports standard protocols to provide single sign-on and delegated authorization to web applications in addition to JSON APIs to support the Cloud Controller and team features of Cloud Foundry
* supports APIs and a basic login/approval UI for web client apps
* supports APIs for user account management for an external web UI (i.e. ``www.cloudfoundry.com``)

Rather than trigger arguments about how RESTful these APIs are we'll just refer to them as JSON APIs. Most of them are defined by the specs for the OAuth2_, `OpenID Connect`_, and SCIM_ standards.

.. _OAuth2: http://tools.ietf.org/html/rfc6749
.. _OpenID Connect: http://openid.net/openid-connect
.. _SCIM: http://simplecloud.info

Scopes authorized by the UAA
============================
The UAA itself is also performing authorization based on the ``scope`` claim in the JWT token for it's operation.
Here is a summary of the different scopes that are known to the UAA.

* **zones.read** - scope required to invoke the /identity-zones endpoint to read identity zones
* **zones.write** - scope required to invoke the /identity-zones endpoint to create and update identity zones
* **idps.read** - read only scopes to retrieve identity providers under /identity-providers
* **idps.write** - create and update identity providers under /identity-providers
* **clients.admin** - super user scope to create, modify and delete clients
* **clients.write** - scope required to create and modify clients. The scopes are limited to be prefixed with the scope holder's client id. For example, id:testclient authorities:client.write may create a client that has scopes that have the 'testclient.' prefix. Authorities are limited to uaa.resource
* **clients.read** - scope to read information about clients
* **clients.secret** - ``/oauth/clients/*/secret`` endpoint. Scope required to change the password of a client. Considered an admin scope.
* **clients.trust** - ``/oauth/clients/*/clientjwt`` endpoint. Scope required to change the JWT configuration of a client. Considered an admin scope.
* **scim.write** - Admin write access to all SCIM endpoints, ``/Users``, ``/Groups/``.
* **scim.read** - Admin read access to all SCIM endpoints, ``/Users``, ``/Groups/``.
* **scim.create** - Reduced scope to be able to create a user using ``POST /Users`` (get verification links ``GET /Users/{id}/verify-link`` or verify their account using ``GET /Users/{id}/verify``) but not be able to modify, read or delete users.
* **scim.userids** - ``/ids/Users`` - Required to convert a username+origin to a user ID and vice versa.
* **scim.zones** - Limited scope that only allows adding/removing a user to/from `zone management groups`_ under the path /Groups/zones
* **scim.invite** - Scope required by a client in order to participate in invitations using the ``/invite_users`` endpoint.
* **password.write** - ``/User*/*/password`` endpoint. Admin scope to change a user's password.
* **oauth.approval** - ``/approvals`` endpoint. Scope required to be able to approve/disapprove clients to act on a user's behalf. This is a default scope defined in uaa.yml.
* **oauth.login** - Scope used to indicate a login application, such as external login servers, to perform trusted operations, such as create users not authenticated in the UAA.
* **approvals.me** - not currently used
* **openid** - Required to access the /userinfo endpoint. Intended for OpenID clients.
* **groups.update** - Allows a group to be updated. Can also be accomplished with ``scim.write``
* **uaa.user** - scope to indicate this is a user, also required in the token if using `API Authorization Requests Code: ``GET /oauth/authorize`` (non standard /oauth/authorize)`_
* **uaa.resource** - scope to indicate this is a resource server, used for the /check_token endpoint
* **uaa.admin** - scope to indicate this is the super user
* **uaa.none** - scope to indicate that this client will not be performing actions on behalf of a user

.. _`zone management groups`:

Zone Management Scopes

* **zones.<zone id>.admin** - scope that permits operations in a designated zone by authenticating against the default zone, such as create identity providers or clients in another zone (used together with the X-Identity-Zone-Id header)
* **zones.<zone id>.read** - scope that permits reading the given identity zone (used together with the X-Identity-Zone-Id header)
* **zones.<zone id>.clients.admin** - translates into clients.admin after zone switch is complete (used together with the X-Identity-Zone-Id header)
* **zones.<zone id>.clients.read** - translates into clients.read after zone switch is complete (used together with the X-Identity-Zone-Id header)
* **zones.<zone id>.clients.write** - translates into clients.write after zone switch is complete (used together with the X-Identity-Zone-Id header)
* **zones.<zone id>.scim.read** - translates into scim.read after zone switch is complete (used together with the X-Identity-Zone-Id header)
* **zones.<zone id>.scim.create** - translates into scim.create after zone switch is complete (used together with the X-Identity-Zone-Id header)
* **zones.<zone id>.scim.write** - translates into scim.write after zone switch is complete (used together with the X-Identity-Zone-Id header)
* **zones.<zone id>.idps.read** - translates into idps.read after zone switch is complete (used together with the X-Identity-Zone-Id header)

A Note on Filtering
===================
In several of the API calls, especially around the SCIM endpoints, ``/Users`` and ``/Groups``
there is an option to specify filters. These filters are implemented in accordance with
a SCIM specification [on resource queries](http://www.simplecloud.info/specs/draft-scim-api-01.html#query-resources).

Filtering supports

Attribute operators

* eq - equalsIgnoreCase
* co - contains - in SQL becomes 'like %value%', case insensitive
* sw - starts with - in SQL becomes 'like value%', case insensitive
* pr - present - in SQL becomes 'IS NOT NULL'
* gt - greater than - ``>``
* ge - greater or equal than - ``>=``
* lt - less than - ``<``
* le - less or equals than - ``<=``

Logical operators

* and - logical and
* or - logical or

Grouping operators

* Group expressions in parenthesis ``(`` expression ``)`` to set precedence for operators

There are four different data types

* string literals - values must always be enclosed in double quotes ``"``, and double quotes must be JSON escaped
  (with a slash ``\``)
* date times - values must always be enclosed in double quotes, format is ``yyyy-MM-dd'T'HH:mm:ss.SSS'Z'``
* boolean - values must be either ``true`` or ``false`` and not enclosed in quotes
* numerical - values are not enclosed in quotes, and can contain numbers and a dot for decimal delimitation

For complete information on filters and pagination, please review the [specification](http://www.simplecloud.info/specs/draft-scim-api-01.html#query-resources)

User column names
-----------------
The following column names can be used for querying a user

* id - string, UUID of the user
* username - string
* email or emails.value - string
* givenname - string
* familyname - string
* active - boolean
* phonenumber - string
* verified - boolean
* origin - string
* external_id - string
* created or meta.created - date
* lastmodified or meta.lastmodified - date
* version or meta.version - number

The following column names can be used for querying a group

* id - string, UUID of the group
* displayname - string
* created or meta.created - date
* lastmodified or meta.lastmodified - date
* version or meta.version - number

Configuration Options
=====================

Several modes of operation and other optional features can be set in configuration files.  Settings for a handful of standard scenarios can be externalized and switched using environment variables or system properties.

* Internal username/password authentication source

  The UAA manages a user account database. These accounts can be used for password based authentication similar to existing Cloud Foundry user accounts. The UAA accounts can be configured with password policy such as length, accepted/required character types, expiration times, reset policy, etc.

* Other Authentication sources

  * LDAP - LDAP is currently supported for user authentication and group integration

  * SAML - SAML is currently supported for user authentication and group integration. Limitation is that the username returned from the SAML assertion should be an email address

OAuth2 Token Endpoint: ``POST /oauth/token``
============================================
An OAuth2 defined endpoint which accepts authorization code or refresh tokens and provides access_tokens, in the case of authorization code grant. This endpoint also supports client credentials and password grant, which takes the client id and client secret for the former, in addition to username and password in case of the latter. The access_tokens can then be used to gain access to resources within a resource server.
We support all standard OAuth2 grant types, documented in https://tools.ietf.org/html/rfc6749

* Request: ``POST /oauth/token``

=============== =================================================
Request         ``POST /oauth/token``
Authorization   Basic authentication, client ID and client secret
                (or ``client_id`` and ``client_secret`` can
                be provided as url encoded form parameters)
Request Body    the authorization code (form encoded) in the case
                of authorization code grant, e.g.::

                  grant_type=authorization_code
                  code=F45jH
                  redirect_uri=http://example-app.com/welcome

                OR the client credentials (form encoded) in the
                case of client credentials grant, e.g.::

                  grant_type=client_credentials
                  client_id=client
                  client_secret=clientsecret
                  response_type=token

                OR the client and user credentials (form encoded)
                in the case of password grant, e.g.::

                  grant_type=password
                  client_id=client
                  client_secret=clientsecret
                  username=user
                  password=pass

Response Codes  ``200 OK``
Response Body   ::

                  {
                    "access_token":"2YotnFZFEjr1zCsicMWpAA",
                    "token_type":"bearer",
                    "expires_in":3600
                  }
=============== =================================================

Support for additional authorization attributes
-----------------------------------------------

Additional user defined claims can be added to the token by sending them in the token request. The format of the request is as follows::

        authorities={"az_attr":{"external_group":"domain\\group1","external_id":"abcd1234"}}

A sample password grant request is as follows::

        POST /uaa/oauth/token HTTP/1.1
        Host: localhost:8080
        Accept: application/json
        Authorization: Basic YXBwOmFwcGNsaWVudHNlY3JldA==
        "grant_type=password&username=marissa&password=koala&authorities=%7B%22az_attr%22%3A%7B%22external_group%22%3A%22domain%5C%5Cgroup1%22%2C%20%22external_id%22%3A%22abcd1234%22%7D%7D%0A"

The access token will contain an az_attr claim like::

        "az_attr":{"external_group":"domain\\group1","external_id":"abcd1234"}}

These attributes can be requested in an authorization code flow as well.

Authentication and Delegated Authorization APIs
===============================================

This section deals with machine interactions, not with browsers, although some of them may have browsable content for authenticated users.  All machine requests have accept headers indicating JSON (or a derived media type perhaps).

The ``/userinfo`` and ``/oauth/token`` endpoints are specified in the `OpenID Connect`_ and `OAuth2`_ standards and should be used by web applications on a cloud foundry instance.

A Note on OAuth Scope
---------------------

The OAuth2 spec includes a ``scope`` parameter as part of the token granting request which contains a set of scope values.  The spec leaves the business content of the scope up to the participants in the protocol - i.e. the scope values are completely arbitrary and can in principle be chosen by any Resource Server using the tokens.  Clients of the Resource Server have to ask for a valid scope to get a token, but the Authorization Server itself attaches no meaning to the scope - it just passes the value through to the Resource Server.  The UAA implementation of the Authorization Server has a couple of extra scope-related features (by virtue of being implemented in Spring Security where the features originate).

1. There is an optional step in client registration, where a client declares which scopes it will ask for, or alternatively where the Authorization Server can limit the scopes it can ask for. The Authorization Server can then check that token requests contain a valid scope (i.e. one of the set provided on registration).

2. The Resource Servers can each have a unique ID (e.g. a URI). And another optional part of a client registration is to provide a set of allowed resource ids for the client in question.  The Authorization Server binds the allowed resource ids to the token and then provides the information via the ``/check_token`` endpoint (in the ``aud`` claim), so that a Resource Server can check that its own ID is on the allowed list for the token before serving a resource.

Resource IDs have some of the character of a scope, except that the clients themselves don't need to know about them - it is information exchanged between the Authorization and Resource Servers.  The examples in this document use a ``scope`` parameter that indicates a resource server, e.g. a Cloud Controller instance. This is a suggested usage, but whether it is adopted by the real Cloud Controller is not crucial to the system.  Similarly any Resource Server that wants to can check the allowed resource IDs if there are any, but it is not mandatory to do so.

Authorization Code Grant
------------------------

This is a completely vanilla as per the `OAuth2`_ spec, but we give a brief outline here for information purposes.

Browser Requests Code: ``GET /oauth/authorize``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*HTML Responses*

* Request: ``GET /oauth/authorize``
* Request Body: some parameters specified by the spec, appended to the query component using the ``application/x-www-form-urlencoded`` format,

  * ``response_type=code``
  * ``client_id=www``
  * ``scope=read write password``
  * ``redirect_uri`` is optional if a redirect_uri has already been pre-registered for the client www

* Request Header:

  * ``Cookie: JSESSIONID=ADHGFKHDSJGFGF; Path /`` - the authentication cookie for the client with UAA. If there is no cookie user's browser is redirected to ``/login``, and will eventually come back to ``/oauth/authorize``.

* Response Header: location as defined in the spec includes ``access_token`` if successful::

        HTTP/1.1 302 Found
        Location: https://www.cloudfoundry.example.com?code=F45jH
        Set-Cookie: X-Uaa-Csrf=abcdef; Expires=Thu, 04-Aug-2016 18:10:38 GMT; HttpOnly

* Response Codes::

        302 - Found

*Sample uaac command for this flow*

* ``uaac -t token authcode get -c app -s appclientsecret``

*Sample curl commands for this flow*

* ``curl -v "http://localhost:8080/uaa/oauth/authorize?response_type=code&client_id=app&scope=password.write&redirect_uri=http%3A%2F%2Fwww.example.com%2Fcallback" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v http://localhost:8080/uaa/login.do -H "Referer: http://login.cloudfoundry.example.com/login" -H "Accept: application/json" -H "Content-Type: application/x-www-form-urlencoded" -d "username=marissa&password=koala&X-Uaa-Csrf=abcdef" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v "http://localhost:8080/uaa/oauth/authorize?response_type=code&client_id=app&scope=password.write&redirect_uri=http%3A%2F%2Fwww.example.com%2Fcallback" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v http://localhost:8080/uaa/oauth/authorize -d "scope.0=scope.password.write&user_oauth_approval=true" --cookie cookies.txt --cookie-jar cookies.txt``

Non-Browser Requests Code: ``GET /oauth/authorize``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*JSON Responses*

If the client asks for a JSON response (with an ``Accept`` header), and
the user has not approved the grant yet, the UAA sends a JSON object
with some useful information that can be rendered for a user to read
and explicitly approve the grant::


    {
      "message":"To confirm or deny access POST to the following locations with the parameters requested.",
      "scopes":[
        {"text":"Access your data with scope 'openid'","code":"scope.openid"},
        {"text":"Access your 'cloud_controller' resources with scope 'read'","code":"scope.cloud_controller.read"},
        ...],
      ...,
      "client_id":"idtestapp",
      "redirect_uri":"http://nowhere.com",
      "options":{
        "deny":{"location":"https://uaa.cloudfoundry.com/oauth/authorize","value":"false","path":"/oauth/authorize","key":"user_oauth_approval"},
        "confirm":{"location":"https://uaa.cloudfoundry.com/oauth/authorize","value":"true","path":"/oauth/authorize","key":"user_oauth_approval"}
      }
    }

The most useful information for constructing a user approval page is
the list of requested scopes, the client id and the requested redirect
URI.

*Sample curl commands for this flow*

* ``curl -v -H "Accept:application/json" "http://localhost:8080/uaa/oauth/authorize?response_type=code&client_id=app&scope=password.write&redirect_uri=http%3A%2F%2Fwww.example.com%2Fcallback" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v -H "Accept:application/json" http://localhost:8080/uaa/login.do -H "Referer: http://login.cloudfoundry.example.com/login" -H "Accept: application/json" -H "Content-Type: application/x-www-form-urlencoded" -d "username=marissa&password=koala&X-Uaa-Csrf=abcdef" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v -H "Accept:application/json" "http://localhost:8080/uaa/oauth/authorize?response_type=code&client_id=app&scope=password.write&redirect_uri=http%3A%2F%2Fwww.example.com%2Fcallback" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v -H "Accept:application/json" http://localhost:8080/uaa/oauth/authorize -d "scope.0=scope.password.write&user_oauth_approval=true" --cookie cookies.txt --cookie-jar cookies.txt``

API Authorization Requests Code: ``GET /oauth/authorize`` (non standard /oauth/authorize)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


* Request: ``GET /oauth/authorize``
* Request Parameters:

  * ``client_id=some_valid_client_id``
  * ``scope=``
  * ``response_type=code``
  * ``redirect_uri`` - optional if the client has a redirect URI already registered.
  * ``state`` - any random string - will be returned in the Location header as a query parameter

* Request Header:

  * Authorization: Bearer <token containing uaa.user scope> - the authentication for this user

* Response Header: Containing the code::

        HTTP/1.1 302 Found
        Location: https://www.cloudfoundry.example.com?code=F45jH&state=<your state>
        or in case of error
        Location: https://www.cloudfoundry.example.com?error=<error code>

* Response Codes::

        302 - Found

*Notes about this API*

* The client must have autoapprove=true, or you will not get a code back
* If the client doesn't have a redirect_uri registered, it is an required parameter of the request
* The token must have scope "uaa.user" in order for this request to succeed

*Sample curl commands for this flow*

* curl -v -H"Authorization: Bearer $TOKEN" "http://localhost:8080/uaa/oauth/authorize?grant_type=authorization_code&client_id=identity&state=mystate&response_type=code&redirect_uri=http://localhost"
* TOKEN can be fetched by: curl -v -XPOST -H"Application/json" -u "cf:" --data "username=marissa&password=koala&client_id=cf&grant_type=password" http://localhost:8080/uaa/oauth/token


Client Obtains Token: ``POST /oauth/token``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See `oauth2 token endpoint`_ below for a more detailed description.

=============== =================================================
Request         ``POST /oauth/token``
Authorization   Basic authentication, client ID and client secret
                (or ``client_id`` and ``client_secret`` can
                be provided as url encoded form parameters)
Request Body    the authorization code (form encoded), e.g.::

                  [client_id=client]
                  [client_secret=clientsecret]
                  grant_type=authorization_code
                  code=F45jH

Response Codes  ``200 OK``
Response Body   ::

                  {
                    "access_token":"2YotnFZFEjr1zCsicMWpAA",
                    "token_type":"bearer",
                    "expires_in":3600
                  }

=============== =================================================

Implicit Grant with Credentials: ``POST /oauth/authorize``
----------------------------------------------------------

An `OAuth2`_ defined endpoint to provide various tokens and authorization codes. An implicit grant is similar to an authorization code grant, but doesn't require a client secret.

For the ``cf`` flows, we use the OAuth2 Implicit grant type (to avoid a second round trip to ``/oauth/token`` and so cf does not need to securely store a client secret or user refresh tokens). The authentication method for the user is undefined by OAuth2 but a POST to this endpoint is acceptable, although a GET must also be supported (see `OAuth2 section 3.1`_).

.. _OAuth2 section 3.1: http://tools.ietf.org/html/rfc6749#section-3.1

Effectively this means that the endpoint is used to authenticate **and** obtain an access token in the same request.  Note the correspondence with the UI endpoints (this is similar to the ``/login`` endpoint with a different representation).

.. note:: A GET mothod is used in the `relevant section <http://tools.ietf.org/html/rfc6749#section-4.2.1>`_ of the spec that talks about the implicit grant, but a POST is explicitly allowed in the section on the ``/oauth/authorize`` endpoint (see `OAuth2 section 3.1`_).

All requests to this endpoint MUST be over SSL.

* Request: ``POST /oauth/authorize``
* Request query component: some parameters specified by the spec, appended to the query component using the "application/x-www-form-urlencoded" format,

  * ``response_type=token``
  * ``client_id=cf``
  * ``scope=read write``
  * ``redirect_uri`` - optional because it can be pre-registered, but a dummy is still needed where cf is concerned (it doesn't redirect) and must be pre-registered, see `Client Registration Administration APIs`_.

* Request body: contains the required information in JSON as returned from the `login information API`_, e.g. username/password for internal authentication, or for LDAP, and others as needed for other authentication types. For example::

        credentials={"username":"dale","password":"secret"}

* Response Header: location as defined in the spec includes ``access_token`` if successful::

        HTTP/1.1 302 Found
        Location: oauth:redirecturi#access_token=2YotnFZFEjr1zCsicMWpAA&token_type=bearer

* Response Codes::

        302 - Found

Implicit Grant for Browsers: ``GET /oauth/authorize``
-----------------------------------------------------

This works similarly to the previous section, but does not require the credentials to be POSTed as is needed for browser flows.

#. The browser redirects to the ``/oauth/authorize`` endpoint with parameters in the query component as per the previous section.
#. The UAA presents the UI to authenticate the user and approve the scopes.
#. If the user authorizes the scopes for the requesting client, the UAA will redirect the browser to the ``redirect_uri`` provided (and pre-registered) by the client.
#. Since the reply parameters are encoded in the location fragment, the client application must get the access token in the reply fragment from user's browser -- typically by returning a page to the browser with some javascript which will post the access token to the client app.

Password Grant with Client and User Credentials: ``POST /oauth/token``
----------------------------------------------------------------------

=============== =================================================
Request         ``POST /oauth/token``
Authorization   Basic authentication, client ID and client secret
                (or ``client_id`` and ``client_secret`` can
                be provided as url encoded form parameters)
Request Body    the ``username`` and ``password`` (form encoded), e.g. ::

                  [client_id=client]
                  [client_secret=clientsecret]
                  grant_type=password
                  username=user
                  password=pass

Response Codes  ``200 OK``
Response Body   ::

                  {
                    "access_token":"2YotnFZFEjr1zCsicMWpAA",
                    "token_type":"bearer",
                    "expires_in":3600
                  }

=============== =================================================

* Request: ``POST /oauth/token``
* Authorization: Basic auth with client_id and client_secret
                 (optionally ``client_id`` and ``client_secret`` can instead
                 be provided as url encoded form parameters)
* Request query component: some parameters specified by the spec, appended to the query component using the "application/x-www-form-urlencoded" format,

  * ``grant_type=password``
  * ``client_id=cf``
  * ``client_secret=cfsecret``
  * ``username=marissa``
  * ``password=koala``
  * ``scope=read write`` - optional. Omit to receive the all claims.
  * ``redirect_uri`` - optional because it can be pre-registered, but a dummy is still needed where cf is concerned (it doesn't redirect) and must be pre-registered, see `Client Registration Administration APIs`_.

Trusted Authentication from Login Server
----------------------------------------

Note: This is not the standard way of creating a user in the UAA. Please refer to the SCIM API endpoint at ``/Users``.
In addition to the normal authentication of the ``/authenticate`` and ``/oauth/authorize`` endpoints described above (cookie-based for browser app and special case for ``cf``) the UAA offers a special channel whereby a trusted client app can authenticate itself and then use the ``/oauth/authorize`` or ``/authenticate`` endpoint by providing minimal information about the user account (but not the password).  This channel is provided so that authentication can be abstracted into a separate "Login" server.  The default client id for the trusted app is ``login``, and this client is registered in the default profile (but not in any other)::

    id: login,
    secret: loginsecret,
    scope: uaa.none,oauth.approvals
    authorized_grant_types: client_credentials,
    authorities: oauth.login

To authenticate the ``/oauth/authorize`` or ``/authenticate`` endpoint using this channel the Login Server has to provide a standard OAuth2 bearer token header _and_ some additional parameters to identify the user: ``source=login`` is mandatory, as is ``username`` and ``origin``, plus optionally ``[email, given_name, family_name]``.  The UAA will lookup the user in its internal database and if it is found the request is authenticated.  The UAA can be configured to automatically register authenicated users that are missing from its database, but this will only work if all the fields are provided.  The response from the UAA (if the Login Server asks for JSON content) has enough information to get approval from the user and pass the response back to the UAA.

Using this trusted channel a Login Server can obtain create a user or perform an Oauth authorization (or tokens directly in the implicit grant) from the UAA, and also have complete control over authentication of the user, and the UI for logging in and approving token grants.

An authorization code grant has two steps (as normal), but instead of a UI response the UAA sends JSON:

Create a user using trusted authenticate channel: /authenticate Request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint lets the login client to retrieve a user_id during an external authentication sequence.
So that the Authentication object in memory can always have a user_id available in the principal.
This endpoint is used when you authenticate a user with another provider not known to the UAA. This will create a shadow account in the UAA representing that user. The user can then be associated with groups so that token's can be generated on the user's behalf.

* Request: ``POST /authenticate``
* Request query component: some parameters specified by the spec, appended to the query component using the "application/x-www-form-urlencoded" format,

  * ``source=login`` - mandatory
  * ``username`` - the user whom the client is acting on behalf of (the authenticated user in the Login Server)
  * ``origin`` - the origin whom the user is authenticated through (the authenticated user in the Login Server)
  * ``email`` - the email of the user, optional
  * ``add_new`` - set to true to create a user that doesn't exist

* Request header:

        Accept: application/json
        Authorization: Bearer <login-client-bearer-token-obtained-from-uaa>

* Request body: empty (or form encoded parameters as above)

* Response header will include a cookie.  This needs to be sent back in the second step (if required) so that the UAA can retrive the state from this request.

* Response body if successful, and user approval is required (example)::

        HTTP/1.1 200 OK
        {
            "username":"YbSgOG",
            "origin":"zkV8lR",
            "user_id":"723def1b-4209-4e2a-99a0-1ac8c6fbb18c"
        }

  the response body contains information about the user that is required for the login server to have access too.

* Response Codes::

        200 - OK
        401 - UNAUTHORIZED (if the token is invalid or user did not exist and add_new was false)


Authorization Step 1: Initial Authorization Request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Request: ``POST /oauth/authorize``
* Request query component: some parameters specified by the spec, appended to the query component using the "application/x-www-form-urlencoded" format,

  * ``response_type=code``
  * ``client_id`` - a registered client id
  * ``redirect_uri`` - a redirect URI registered with the client
  * ``state`` - recommended (a random string that the client app can correlate with the current user session)
  * ``source=login`` - mandatory
  * ``username`` - the user whom the client is acting on behalf of (the authenticated user in the Login Server)
  * ``origin`` - the origin whom the user is authenticated through (the authenticated user in the Login Server)
  * ``email`` - the email of the user, optional
  * ``given_name`` - the given (first) name of the user, optional
  * ``family_name`` - the family (last) name of the user, optional

* Request header:

        Accept: application/json
        Authorization: Bearer <login-client-bearer-token-obtained-from-uaa>

* Request body: empty (or form encoded parameters as above)

* Response header will include a cookie.  This needs to be sent back in the second step (if required) so that the UAA can retrive the state from this request.

* Response body if successful, and user approval is required (example)::

        HTTP/1.1 200 OK
        {
          "message":"To confirm or deny access POST to the following locations with the parameters requested.",
          "scopes":[
             {"text":"Access your data with scope 'openid'","code":"scope.openid"},
             {"text":"Access your 'password' resources with scope 'write'","code":"scope.password.write"},
             ...
          ],
          "auth_request":{...}, // The authorization request
          "client": {
             "scope":[...],
             "client_id":"app",
             "authorized_grant_types":["authorization_code"],
             "authorities":[...]
          },
          "redirect_uri": "http://app.cloudfoundry.com",
          "options":{
              "deny":{"value":"false","key":"user_oauth_approval",...},
              "confirm":{"value":"true","key":"user_oauth_approval",...}
          }
        }

  the response body contains useful information for rendering to a user for approval, e.g. each scope that was requested (prepended with "scope." to facilitate i18n lookups) including a default message text in English describing it.

* Response Codes::

        200 - OK
        403 - FORBIDDEN (if the user has denied approval)
        302 - FOUND (if the grant is already approved)

Authorization Step 2: User Approves Grant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Just a normal POST with approval parameters to ``/oauth/authorize``, including the cookie requested in Step 1 (just like a browser would do).  For example::

        POST /oauth/authorize
        Cookie: JSESSIONID=fkserygfkseyrgfv

        user_oauth_approval=true

Response::

        302 FOUND
        Location: https://app.cloudfoundry.com?code=jhkgh&state=kjhdafg


OAuth2 Token Validation Service: ``POST /check_token``
------------------------------------------------------

An endpoint that allows a resource server such as the cloud controller to validate an access token. Interactions between the resource server and the authorization provider are not specified in OAuth2, so we are adding this endpoint. The request should be over SSL and use basic auth with the shared secret between the UAA and the resource server (which is stored as a client app registration). The POST body should be the access token and the response includes the userID, user_name and scope of the token in json format.  The client (not the user) is authenticated via basic auth for this call.

OAuth2 access tokens are opaque to clients, but can be decoded by resource servers to obtain all needed information such as userID, scope(s), lifetime, user attributes. If the token is encrypted witha shared sceret between the UAA are resource server it can be decoded without contacting the UAA. However, it may be useful -- at least during development -- for the UAA to specify a short, opaque token and then provide a way for the resource server to return it to the UAA to validate and open. That is what this endpoint does. It does not return general user account information like the /userinfo endpoint, it is specifically to validate and return the information represented by access token that the user presented to the resource server.

This endpoint mirrors the OpenID Connect ``/check_id`` endpoint, so not very RESTful, but we want to make it look and feel like the others. The endpoint is not part of any spec, but it is a useful tool to have for anyone implementing an OAuth2 Resource Server.

* Request: uses basic authorization with ``base64(resource_server:shared_secret)`` assuming the caller (a resource server) is actually also a registered client and has `uaa.resource` authority::

        POST /check_token HTTP/1.1
        Host: server.example.com
        Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        Content-Type: application/x-www-form-urlencoded

        token=eyJ0eXAiOiJKV1QiL

* Successful Response::

        HTTP/1.1 200 OK
        Content-Type: application/json

        {
            "jti":"4657c1a8-b2d0-4304-b1fe-7bdc203d944f",
            "aud":["openid","cloud_controller"],
            "scope":["read"],
            "email":"marissa@test.org",
            "exp":138943173,
            "user_id":"41750ae1-b2d0-4304-b1fe-7bdc24256387",
            "user_name":"marissa",
            "client_id":"cf"
        }

Checking for scopes:
The caller can specify a list of ``scopes`` in the request in order to validate that the token has those scopes.

* Request::

        POST /check_token HTTP/1.1
        Host: server.example.com
        Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        Content-Type: application/x-www-form-encoded

        token=eyJ0eXAiOiJKV1QiL
        scopes=read,disallowed_scope

* Response::

        HTTP/1.1 400 Bad Request
        Content-Type: application/json

        {
            "error":"invalid_scope",
            "error_description":"Some requested scopes are missing: disallowed_scope"
        }

Notes:

* The ``user_name`` is the same as you get from the `OpenID Connect`_ ``/userinfo`` endpoint.  The ``user_id`` field is the same as you would use to get the full user profile from ``/Users``.
* Many of the fields in the response are a courtesy, allowing the caller to avoid further round trip queries to pick up the same information (e.g. via the ``/Users`` endpoint).
* The ``aud`` claim is the resource ids that are the audience for the token.  A Resource Server should check that it is on this list or else reject the token.
* The ``client_id`` data represent the client that the token was granted for, not the caller.  The value can be used by the caller, for example, to verify that the client has been granted permission to access a resource.
* Error Responses: see `OAuth2 Error responses <http://tools.ietf.org/html/rfc6749#section-5.2>`_ and this addition::

            HTTP/1.1 400 Bad Request
            Content-Type: application/json
            Cache-Control: no-store
            Pragma: no-cache

            { "error":"invalid_token" }

.. _oauth2 token endpoint:


OAuth2 Token Revocation Service/Client: ``GET /oauth/token/revoke/client/{client-id}``
--------------------------------------------------------------------------------------

An endpoint that allows all tokens for a specific client to be revoked
* Request: uses token authorization and requires `uaa.admin` scope::

        GET /oauth/token/revoke/client/{client-id} HTTP/1.1
        Host: server.example.com
        Authorization: Bearer <uaa.admin> token

* Successful Response::

        HTTP/1.1 200 OK

* Error Response::

        HTTP/1.1 401 Unauthorized - Authentication is not sufficient
        HTTP/1.1 403 Forbidden - Authenticated, but uaa.admin scope is not present
        HTTP/1.1 404 Not Found - Client ID is invalid

OAuth2 Token Revocal Service/User: ``GET /oauth/token/revoke/user/{user-id}``
-----------------------------------------------------------------------------

An endpoint that allows all tokens for a specific user to be revoked
* Request: uses token authorization and requires `uaa.admin` scope::

        GET /oauth/token/revoke/user/{user-id} HTTP/1.1
        Host: server.example.com
        Authorization: Bearer <uaa.admin> token

* Successful Response::

        HTTP/1.1 200 OK

* Error Response::

        HTTP/1.1 401 Unauthorized - Authentication is not sufficient
        HTTP/1.1 403 Forbidden - Authenticated, but uaa.admin scope is not present
        HTTP/1.1 404 Not Found - User ID is invalid



OpenID User Info Endpoint: ``GET /userinfo``
--------------------------------------------

An OAuth2 protected resource and an OpenID Connect endpoint. Given an appropriate access\_token, returns information about a user. Defined fields include various standard user profile fields. The response may include other user information such as group membership.

=========== ===============================================
Request     ``GET /userinfo``
Response    ``{"user_id":"olds","email":"olds@vmare.com"}``
=========== ===============================================

.. _login information api:

Login Information API: ``GET /login``
-------------------------------------

An endpoint which returns login information, e.g prompts for authorization codes or one-time passwords. This allows cf to determine what login information it should collect from the user.

This call will be unauthenticated.

================  ===============================================
Request           ``GET /login`` or ``GET /info``
Request body      *empty*
Response body     *example* ::

                    HTTP/1.1 200 OK
                    Content-Type: application/json

                    "prompt": {
                        "email":["text", "validated email address"],
                        "password": ["password", "your UAA password" ]
                        "otp":["password", "security code"],
                    }

================  ===============================================

Identity Zone Management APIs
=============================

The UAA supports multi tenancy. This is referred to as identity zones. An identity zones is accessed through a unique subdomain. If the standard UAA responds to https://uaa.10.244.0.34.xip.io a zone on this UAA would be accessed through https://testzone1.uaa.10.244.0.34.xip.io

A zone contains a unique identifier as well as a unique subdomain::

                    {
                        "id":"testzone1",
                        "subdomain":"testzone1",
                        "name":"The Twiglet Zone[testzone1]",
                        "version":0,
                        "description":"Like the Twilight Zone but tastier[testzone1].",
                        "created":1426258488910,
                        "last_modified":1426258488910
                    }

The subdomain field will be converted into lowercase upon creation or update of an identity zone.
This way the UAA has an easy way to query the database for a zone based on a hostname.
The UAA by default creates a ``default zone``. This zone will always be present, the ID will always be
'uaa', and the subdomain is blank::

                    {
                        "id": "uaa",
                        "subdomain": "",
                        "name": "uaa",
                        "version": 0,
                        "description": "The system zone for backwards compatibility",
                        "created": 946710000000,
                        "last_modified": 946710000000
                    }


Create or Update Identity Zones: ``POST or PUT /identity-zones``
----------------------------------------------------------------
An identity zone is created using a POST with an IdentityZone object. If the object contains an id, this id will be used as the identifier, otherwise an identifier will be generated. Once a zone has been created, the UAA will start accepting requests on the subdomain defined in the subdomain field of the identity zone.
When an Identity Zone is created, an internal Identity Provider is automatically created with the default password policy.

POST and PUT requires the ``zones.write`` or ``zones.<zone id>.admin``  scope.

================  =============================================================================================================
Request           ``POST /identity-zones`` or ``PUT /identity-zones/{id}``
Request Header    Authorization: Bearer Token containing ``zones.write`` or ``zones.<zone id>.admin``
Request body      *example* ::

                    {
                        "id": "testzone1",
                        "subdomain": "testzone1",
                        "config":
                        {
                            "links": {
                                "homeRedirect": "http://some.redirect.com/redirect",
                                "logout": {
                                    "disableRedirectParameter": false,
                                    "redirectParameterName": "redirect",
                                    "redirectUrl": "/configured_login",
                                    "whitelist": [
                                        "https://url1.domain1.com/logout-success",
                                        "https://url2.domain2.com/logout-success"
                                    ]
                                },
                                "selfService": {
                                    "passwd": "/configured_passwd",
                                    "selfServiceLinksEnabled": false,
                                    "signup": "/configured_signup"
                                }
                            },
                            "prompts": [
                                {
                                    "name": "username",
                                    "text": "Username",
                                    "type": "text"
                                },
                                {
                                    "name": "password",
                                    "text": "Your Secret",
                                    "type": "password"
                                },
                                {
                                    "name": "passcode",
                                    "text": "Temporary Authentication Code ( Get one at https://login.some.test.domain.com:555/uaa/passcode )",
                                    "type": "password"
                                }
                            ],
                            "samlConfig": {
                                "certificate": null,
                                "privateKey": null,
                                "privateKeyPassword": null,
                                "requestSigned": true,
                                "wantAssertionSigned": false
                            },
                            "tokenPolicy": {
                                "accessTokenValidity": 4800,
                                "refreshTokenValidity": 9600,
                                "activeKeyId": "key-id-1",
                                "keys": {
                                    "key-id-1": {
                                        "signingKey": "pr1V4T3_keY_t3xT"
                                    },
                                    "key-id-2": {
                                        "signingKey": "an07h3r_PRivA73_K3y"
                                    }
                                }
                            }
                        }
                        "name": "The Twiglet Zone",
                        "description": "Like the Twilight Zone but tastier."
                    }


Response body     *example* ::

                    HTTP/1.1 200 OK
                    Content-Type: application/json

                    {
                        "id": "testzone1",
                        "subdomain": "testzone1",
                        "config":
                        {
                            "tokenPolicy":
                            {
                                "accessTokenValidity": 43200,
                                "refreshTokenValidity": 2592000
                            },
                            "samlConfig":
                            {
                                "requestSigned": false,
                                "wantAssertionSigned": false
                            }
                        },
                        "name": "The Twiglet Zone[testzone1]",
                        "version": 0,
                        "description": "Like the Twilight Zone but tastier[testzone1].",
                        "created": 1426260091139,
                        "last_modified": 1426260091139
                    }

Response          *Codes* ::

                    201 - Created - and returns the created identity zone
                    200 - OK - for PUT and GET
                    400 - Bad Request
                    401 - Unauthorized
                    403 - Forbidden - insufficient scope
                    404 - Not Found - Update to non existent zone

Fields            *Available Fields* ::

                    Identity Zone Fields
                    ==============================  ====================  =========  ========================================================================================================================================================================
                    id                              String(36)            Required   Unique identifier for this zone, often set to same as subdomain
                    subdomain                       String(255)           Required   Unique subdomain for the running instance. May only contain legal characters for a sub domain name
                    name                            String(255)           Required   Human readable zone name
                    version                         int                   Optional   Reserved for future use of E-Tag versioning
                    description                     String                Optional   Description of the zone
                    created                         epoch timestamp       Auto       UAA sets the creation date
                    last_modified                   epoch timestamp       Auto       UAA sets the modification date

                    Identity Zone Configuration     (provided in JSON format as part of the ``config`` field on the Identity Zone - See class org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration)
                    ==============================  ====================  =========  ========================================================================================================================================================================
                    tokenPolicy                     TokenPolicy           Optional   Various fields pertaining to the JWT access and refresh tokens. See `Token Policy` section below for details.
                    samlConfig                      SamlConfig            Optional   Various fields pertaining to SAML identity provider configuration. See ``SamlConfig`` section below for details.

                    Token Policy ``TokenPolicy``    (part of Identity Zone Configuration - See class org.cloudfoundry.identity.uaa.zone.TokenPolicy)
                    ==============================  ====================  =========  ========================================================================================================================================================================
                    accessTokenValidity             int                   Optional   How long the access token is valid for in seconds.
                    refreshTokenValidity            int                   Optional   How long the refresh token is valid for seconds.
                    keys                            Map                   Optional   A map specifying current and historical JWT signing keys, with unique IDs for referring to them. For an explanation of key rotation, see ``/token_key``.
                    activeKeyId                     String                Required   The ID of the signing key that should be used for signing tokens. Optional if only one signing key is specified. For an explanation of key rotation, see ``/token_key``.

                    SAML Identity Provider          Configuration ``SamlConfig`` (part of Identity Zone Configuration - See class org.cloudfoundry.identity.uaa.zone.SamlConfig)
                    ==============================  ====================  =========  ========================================================================================================================================================================
                    requestSigned                   Boolean               Optional   Exposed SAML metadata property. If ``true``, the service provider will sign all outgoing authentication requests. Defaults to ``true``.
                    wantAssertionSigned             Boolean               Optional   Exposed SAML metadata property. If ``true``, all assertions received by the SAML provider must be signed. Defaults to ``true``.
                    certificate                     String                Optional   Exposed SAML metadata property. The certificate used to sign all communications.  Reserved for future use.
                    privateKey                      String                Optional   Exposed SAML metadata property. The SAML provider's private key.  Reserved for future use.
                    privateKeyPassword              String                Optional   Exposed SAML metadata property. The SAML provider's private key password.  Reserved for future use.

                    =============================   ====================  =========  ========================================================================================================================================================================

Curl Example      POST (Token contains ``zones.write`` scope) ::

                    curl -v -H"Authorization: Bearer $TOKEN" \
                      -d '{"id":"testzone1","subdomain":"testzone1","name":"The Twiglet Zone","description":"Like the Twilight Zone but tastier."}' \
                      -H"Accept:application/json" \
                      -H"Content-Type:application/json" \
                      -XPOST \
                      http://localhost:8080/uaa/identity-zones

                  PUT (Token contains ``zones.write`` scope) ::

                    curl -v -H"Authorization: Bearer $TOKEN" \
                      -d '{"id":"testzone1","subdomain":"testzone-1","name":"The Twiglet Dash Zone","description":"Like the Twilight Zone but tastier."}' \
                      -H"Accept:application/json" \
                      -H"Content-Type:application/json" \
                      -XPUT http://localhost:8080/uaa/identity-zones/testzone1

================  =============================================================================================================

Note that if you specify a subdomain in mixed or upper case, it will be converted into lower case before
stored in the database.

Sequential example of creating a zone and creating an admin client in that zone
-------------------------------------------------------------------------------
Example::

    uaac target http://localhost:8080/uaa

    uaac token client get admin -s adminsecret

    uaac client update admin --authorities "uaa.admin,clients.read,clients.write,clients.secret,scim.read,scim.write,clients.admin,zones.write"

    uaac token client get admin -s adminsecret

    uaac -t curl -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "id":"testzone1", "subdomain":"testzone1", "name":"The Twiglet Zone[testzone1]", "version":0, "description":"Like the Twilight Zone but tastier[testzone1]."}' /identity-zones

    uaac -t curl -H"X-Identity-Zone-Id:testzone1" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "adminsecret", "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

    uaac target http://testzone1.localhost:8080/uaa

    uaac token client get admin -s adminsecret

    uaac token decode

All operations after this, are exactly the same as against the default zone.


List Identity Zones: ``GET /identity-zones``
--------------------------------------------

==============  ===========================================================================
Request         ``GET /identity-zones``
Request Header  Authorization: Bearer Token containing ``zones.read`` or ``zones.<zone id>.admin``
Response code   ``200 OK``
Response body   *example* ::

                  HTTP/1.1 200 OK
                  Content-Type: application/json
                  [
                      {
                          "id": "uaa",
                          "subdomain": "",
                          "name": "uaa",
                          "version": 0,
                          "description": "The system zone for backwards compatibility",
                          "created": 946710000000,
                          "last_modified": 946710000000
                      },
                      {
                          "id":"testzone1",
                          "subdomain":"testzone1",
                          "name":"The Twiglet Zone[testzone1]",
                          "version":0,
                          "description":"Like the Twilight Zone but tastier[testzone1].",
                          "created":1426260091139,
                          "last_modified":1426260091139
                      }
                  ]

==============  ===========================================================================

Get single identity zone: ``GET /identity-zones/{identityZoneId}``
------------------------------------------------------------------

==============  ===========================================================================
Request         ``GET /identity-zones/{identityZoneId}``
Request Header  Authorization: Bearer Token containing ``zones.read`` or ``zones.<zone id>.admin`` or ``zones.<zone id>.read``
Response code   ``200 OK``
Response body   *example* ::

                  HTTP/1.1 200 OK
                  Content-Type: application/json
                      {
                          "id": "identity-zone-id",
                          "subdomain": "test",
                          "name": "test",
                          "version": 0,
                          "description": "The test zone",
                          "created": 946710000000,
                          "last_modified": 946710000000
                      }

==============  ===========================================================================

Delete single identity zone: ``DELETE /identity-zones/{identityZoneId}``
------------------------------------------------------------------------

==============  ===========================================================================
Request         ``DELETE /identity-zones/{identityZoneId}``
Request Header  Authorization: Bearer Token containing ``zones.write``
Response code   ``200 OK``
Response body   *example* ::

                  HTTP/1.1 200 OK
                  Content-Type: application/json
                      {
                          "id": "identity-zone-id",
                          "subdomain": "test",
                          "name": "test",
                          "version": 0,
                          "description": "The test zone",
                          "created": 946710000000,
                          "last_modified": 946710000000
                      }

==============  ===========================================================================

Identity Zone clients API: ``/identity-zones/clients``
------------------------------------------------------

With the ``zones.write`` scope, limited clients can be created in an identity zone through this endpoint. This client can only be used to support web SSO using the authorization code flow, and using the zone's internal Identity Provider.

Client limitations

====================  ===========================
Authorization Type    authorization_code
Scopes                openid
Authorities           uaa.resource
Allowed Providers     uaa
====================  ===========================

Identity Zone Client API Documentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

================  ====================================================================================================================================================
Request           ``POST /identity-zones/{identityZoneId}/clients``
Request Header    Authorization: Bearer Token containing ``zones.write``
Request body      *example* ::

                    {
                        "client_id" : "limited-client",
                        "client_secret" : "limited-client-secret",
                        "authorized_grant_types" : ["authorization_code"],
                        "scope" : ["openid"],
                        "authorities" : ["uaa.resource"],
                        "allowedproviders" : ["uaa"]
                    }

Response body     *example* ::

                    HTTP/1.1 201 Created
                    Content-Type: application/json

                    {
                        "client_id" : "limited-client",
                        "client_secret" : "limited-client-secret",
                        "authorized_grant_types" : ["authorization_code"],
                        "scope" : ["openid"],
                        "authorities" : ["uaa.resource"],
                        "resource_ids" : ["none"],
                        "allowedproviders" : ["uaa"],
                        "createdwith" : "zones.write"
                    }

Response          *Codes* ::

                    201 - Created - and returns the created client
                    400 - Bad Request - the client was rejected due to validation
                    401 - Unauthorized
                    403 - Forbidden - insufficient scope

Fields            *Available Fields* ::

                    ======================  ===============  ======== =======================================================
                    client_id               String(36)       Required Unique identifier for this client - used in API requests as basic auth or client_id parameter
                    client_secret           String(255)      Required Password for the client - used in API requests as basic auth or client_secret parameter
                    authorized_grant_types  List<String>     Required Limited to ["authorization_code"]
                    scope                   List<String>     Required Limited to ["openid"]
                    authorities             List<String>     Required Limited to ["uaa.resource"]
                    allowedproviders        List<String>     Required Limited to ["uaa"]
                    autoapprove             List<String>     Optional Set to ["openid"] if the UAA should auto approve this scope on the user's behalf
                    redirect_uri            String           Optional To enforce a secure redirect, set this to the applications destination URL
                    access_token_validity   int              Optional Value in seconds for how long an access token is valid for
                    refresh_token_validity  int              Optional Value in seconds for how long a refresh token is valid for
                    resource_ids            List<String>     Auto     Set to ["none"]
                    createdwith             String           Auto     Set to "zones.write"
                    created                 epoch timestamp  Auto     UAA sets the creation date
                    last_modified           epoch timestamp  Auto     UAA sets the modification date

Curl Example      POST (Token contains ``zones.write`` scope) ::

                    curl -v -H"Authorization:Bearer $TOKEN" \
                      -XPOST -H'Content-type: application/json' \
                      -d '{"client_id" : "limited-client",  "client_secret" : "limited-client-secret", "authorized_grant_types" : ["authorization_code"],"scope" : ["openid"],"authorities" : ["uaa.resource"], "allowedproviders" : ["uaa"]}' \
                      http://localhost:8080/uaa/identity-zones/testzone1/clients

================  ====================================================================================================================================================


A client created through this endpoint can be deleted through this endpoint as well using the ``zones.write`` scope. The deleted client is returned in the response.

================  ========================================================================================
Request           ``DELETE /identity-zones/{identityZoneId}/clients/{clientId}``
Request Header    Authorization: Bearer Token containing ``zones.write``
Request body      None


Response body     *example* ::

                    HTTP/1.1 200 OK
                    Content-Type: application/json

                    {
                        "client_id" : "limited-client",
                        "client_secret" : "limited-client-secret",
                        "authorized_grant_types" : ["authorization_code"],
                        "scope" : ["openid"],
                        "authorities" : ["uaa.resource"],
                        "resource_ids" : ["none"],
                        "allowedproviders" : ["uaa"],
                        "createdwith" : "zones.write"
                    }

* Response        *Codes* ::

                    200 - OK - the client was deleted
                    400 - Bad Request - the client was not deleted because it was not created using this endpoint
                    401 - Unauthorized
                    403 - Forbidden - insufficient scope
                    404 - Not Found - Client does not exist

Curl Example      POST (Token contains ``zones.write`` scope) :: ::

                    curl -v -H"Authorization:Bearer $TOKEN" -XDELETE http://localhost:8080/uaa/identity-zones/testzone1/clients/limited-client

================  ========================================================================================

To create an arbitrary client in an Identity Zone, you must have the scope of zones.<zone id>.admin. See create_zone_administrator_ to assign that scope to a user, then as that user, use the /oauth/clients endpoints, being sure to include the X-Identity-Zone-Id: <zone-id> header.

Identity Provider API: ``/identity-providers``
----------------------------------------------

Within an identity zone you can have one or more identity providers. Identity providers are authentication sources for a user. Each identity zone will have a default identity provider named ``uaa``, with a type ``uaa`` and originKey='uaa'. This is the internal user database for each zone and is represented by the SCIM schema for users.

The UAA supports two additional types of identity providers, SAML and LDAP, and these providers can be created for a given zone.
Adding providers can be done by users that are Zone Administrators. These users are users in the UAA (default) zone, that have the scope ``zones.{zone id}.admin``. You can also create clients or users in the zone itself with the scopes ``idps.read`` and ``idps.write`` to perform these operations.

Identity providers of type ``uaa`` are created with a default password policy. Password policies are JSON objects and can be updated by putting a new password policy object in the config field and doing an HTTP PUT. An example password policy can be found below.


Steps to create a zone administrator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A zone administrator has the scope ``zones.{zone id}.admin`` scope. In this example, we'll go ahead and use the cf-uaac Ruby Gem to simplify the commands a little bit.

* Install the ``uaac`` gem
  ::

    gem install cf-uaac

* Target the UAA and get a token for the ``identity`` client
  ::

    uaac target http://localhost:8080/uaa
    uaac token client get identity -s identitysecret

* Create the ``testzone1`` zone
  ::

    uaac curl -d '{"identity_zone":{"id":"testzone1","subdomain":"testzone1","name":"The Twiglet Zone[testzone1]","version":0,"description":"Like the Twilight Zone but tastier[testzone1].","created":1424995153031,"last_modified":1424995153031},"client_details":null}' -H"Accept:application/json" -H"Content-Type:application/json" -XPOST /identity-zone

* We need a User ID in order to make a zone admin. We'll use test user ``marissa``
  ::

    uaac token client get admin -s adminsecret
    user_id=uaac users -a id 'username eq "marissa"' |grep id |awk '{print $2}' && echo $user_id
    echo $User_id

* Get the ``identity`` token again and add zones.testzone1.admin to ``marissa``
  ::

    uaac token client get identity -s identitysecret
    uaac curl -d '{"schemas":["urn:scim:schemas:core:1.0"],"displayName":"zones.testzone1.admin","members":[{"origin":"uaa","type":"USER","value":"'$user_id'"}],"meta":{"version":0,"created":"2015-02-26T16:59:13.614Z"}}' -H"Accept:application/json" -H"Content-Type:application/json" -XPOST /Groups/zones

* Retrieve the zone administrator token (log in with marissa/koala)
  ::

    uaac token authcode get -c identity -s identitysecret
    uaac token decode

You will be able to see all tokens used by these steps in the ``~/.uaac.yml`` file.

Identity Provider API Documentation
-----------------------------------

==================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request             ``GET /identity-providers/{id}`` (returns a single provider) or ``GET /identity-providers`` (returns an array of providers)
Header              ``X-Identity-Zone-Id`` (if using zones.<id>.admin scope against default UAA zone)
Scopes Required     ``zones.<zone id>.admin`` or ``idps.read``
Request Parameters  active_only (optional parameter for /identity-providers). Set to true to retrieve only active Identity Providers
Response body       *example* ::

                     HTTP/1.1 200 OK
                     Content-Type: application/json

                     [
                        {
                            "id":"50cf6125-4372-475e-94e8-c43f84111e75",
                            "originKey":"uaa",
                            "name":"internal",
                            "type":"internal",
                            "config":null,
                            "version":0,
                            "created":1426260091149,
                            "active":true,
                            "identityZoneId":"testzone1",
                            "last_modified":1426260091149
                        }
                     ]

==================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``POST /identity-providers`` or ``PUT /identity-providers/{id}``
Header            ``X-Identity-Zone-Id`` (if using zones.<id>.admin scope against default UAA zone)
Scopes Required   ``zones.<zone id>.admin`` or ``idps.read`` and ``idps.write``
Request body      *example* ::

                    {
                        "originKey":"uaa",
                        "name":"internal",
                        "type":"internal",
                        "config":null,
                        "version":0,
                        "created":1426260091149,
                        "active":true,
                        "identityZoneId":"testzone1"
                    }

Response body     *example* ::

                    HTTP/1.1 200 OK
                    Content-Type: application/json

                    {
                        "id":"50cf6125-4372-475e-94e8-c43f84111e75",
                        "originKey":"uaa",
                        "name":"internal",
                        "type":"internal",
                        "config":null,
                        "version":0,
                        "created":1426260091149,
                        "active":true,
                        "identityZoneId":"testzone1",
                        "last_modified":1426260091149
                    }

* Response        *Codes* ::

                    201 - Created - and returns the body of the created identity provider
                    200 - Ok - for PUT request to update the zone
                    400 - Bad Request
                    401 - Unauthorized
                    403 - Forbidden - insufficient scope
                    422 - Unprocessable Entity

Fields            *Available Fields* ::

                    Identity Provider Fields
                    ================================  ===============  ======== =======================================================
                    id                                String(36)       Auto     Unique identifier for this provider - GUID generated by the UAA
                    name                              String(255)      Required Human readable name for this provider
                    type                              String           Required Value must be either "saml", "ldap" or "internal"
                    originKey                         String           Required Must be either an alias for a SAML/OAuth provider or the value "ldap" for an LDAP provider. If the type is "internal", the originKey is "uaa"
                    config                            String           Required IDP Configuration in JSON format, see below
                    active                            boolean          Optional When set to true, this provider is active. When a provider is deleted this value is set to false
                    identityZoneId                    String           Auto     Set to the zone that this provider will be active in. Determined either by the Host header or the zone switch header
                    created                           epoch timestamp  Auto     UAA sets the creation date
                    last_modified                     epoch timestamp  Auto     UAA sets the modification date

                    UAA Provider Configuration (provided in JSON format as part of the ``config`` field on the Identity Provider - See class org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition
                    =============================   =============== ======== =================================================================================================================================================================================================
                    minLength                       int             Required Minimum number of characters for a user provided password, 0+
                    maxLength                       int             Required Maximum number of characters for a user provided password, 1+
                    requireUpperCaseCharacter       int             Required Minimum number of upper case characters for a user provided password, 0+
                    requireLowerCaseCharacter       int             Required Minimum number of lower case characters for a user provided password, 0+
                    requireDigit                    int             Required Minimum number of numbers for a user provided password, 0+
                    requireSpecialCharacter         int             Required Minimum number of special characters for a user provided password, 0+ Valid-List: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
                    expirePasswordInMonths          int             Required Password expiration in months 0+ (0 means expiration is disabled)
                    lockoutPeriodSeconds            int             Required Amount of time in seconds to lockout login attempts after ``lockoutAfterFailures`` attempts reached, 0+
                    lockoutAfterFailures            int             Required Number of login attempts allowed within ``countFailuresWithin`` seconds, 0+
                    countFailuresWithin             int             Required Amount of time in seconds for which past login failures are counted, starting from the current time, 0+
                    disableInternalUserManagement   boolean         Optional When set to true, user management is disabled for this provider, defaults to false
                    emailDomain                     List<String>    Optional List of email domains associated with the UAA provider. If null and no domains are explicitly matched with any other providers, the UAA acts as a catch-all, wherein the email will be associated with the UAA provider. Wildcards supported.
                    providerDescription             String          Optional Human readable name/description of this provider

                    SAML Provider Configuration (provided in JSON format as part of the ``config`` field on the Identity Provider - See class org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition
                    ======================   ======================  ======== =================================================================================================================================================================================================================================================================================================================================================================================================================================================
                    idpEntityAlias           String                  Required Must match ``originKey`` in the provider definition
                    zoneId                   String                  Required Must match ``identityZoneId`` in the provider definition
                    metaDataLocation         String                  Required SAML Metadata - either an XML string or a URL that will deliver XML content
                    nameID                   String                  Optional The name ID to use for the username, default is "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified". Currently the UAA expects the username to be a valid email address.
                    assertionConsumerIndex   int                     Optional SAML assertion consumer index, default is 0. (Deprecated. Does not work if set to anything but 0.)
                    metadataTrustCheck       boolean                 Optional Should metadata be validated, defaults to false
                    showSamlLink             boolean                 Optional Should the SAML login link be displayed on the login page, defaults to false
                    linkText                 String                  Optional Required if the ``showSamlLink`` is set to true.
                    iconUrl                  String                  Optional Reserved for future use
                    emailDomain              List<String>            Optional List of email domains associated with the SAML provider for the purpose of associating users to the correct origin upon invitation. If null or empty list, no invitations are accepted. Wildcards supported.
                    attributeMappings        Map<String, Object>     Optional List of UAA attributes mapped to attributes in the SAML assertion. Currently we support mapping given_name, family_name, email, phone_number and external_groups. Also supports custom user attributes to be populated in the id_token when the `user_attributes` scope is requested. The attributes are pulled out of the user records and have the format `user.attribute.<name of attribute in ID token>: <saml assertion attribute name>`
                    externalGroupsWhitelist  List<String>            Optional List of external groups that will be included in the ID Token if the `roles` scope is requested.
                    providerDescription      String                  Optional Human readable name/description of this provider

                    OAuth Provider Configuration (provided in JSON format as part of the ``config`` field on the Identity Provider - See class org.cloudfoundry.identity.uaa.provider.ExternalOAuthIdentityProviderDefinition
                    ======================   ======================  ======== =================================================================================================================================================================================================================================================================================================================================================================================================================================================
                    alias                    String                  Required Must match ``originKey`` in the provider definition
                    authUrl                  URL                     Required Must be a valid URL that returns the authorization code.
                    tokenUrl                 URL                     Required Must be a valid URL that returns the token
                    tokenKeyUrl              URL                     Optional If specified, must be a valid URL that returns the verification key for the token.
                    tokenKey                 String                  Optional If tokenKeyUrl is not specified, this must be specified. It will be the verification key used to verify tokens.
                    showLinkText             boolean                 Optional Defaults to true
                    linkText                 String                  Optional Required if the ``showLinkText`` is set to true.
                    relyingPartyId           String                  Required The oauth client id for the UAA that is registered with this provider.
                    relyingPartySecret       String                  Required The oauth client secret for the UAA that is registered with this provider.
                    skipSslValidation        boolean                 Optional Defaults to false.
                    attributeMappings        Map<String, Object>     Optional List of UAA attributes mapped to attributes in the JWT. Currently we support mapping given_name, family_name, email, phone_number and external_groups. Also supports custom user attributes to be populated in the id_token when the `user_attributes` scope is requested. The attributes are pulled out of the user records and have the format `user.attribute.<name of attribute in ID token>: <saml assertion attribute name>`
                    externalGroupsWhitelist  List<String>            Optional List of external groups that will be included in the ID Token if the `roles` scope is requested.
                    providerDescription      String                  Optional Human readable name/description of this provider

                    LDAP Provider Configuration (provided in JSON format as part of the ``config`` field on the Identity Provider - See class org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition
                    ======================      ======================  ======== =================================================================================================================================================================================================
                    ldapProfileFile             String                  Required Value must be "ldap/ldap-search-and-bind.xml" (until other configuration options are supported)
                    ldapGroupFile               String                  Required Value must be "ldap/ldap-groups-map-to-scopes.xml" (until other configuration options are supported)
                    baseUrl                     String                  Required URL to LDAP server, starts with ldap:// or ldaps://
                    bindUserDn                  String                  Required Valid user DN for an LDAP record that has permission to search the LDAP tree
                    bindPassword                String                  Required Password for user the above ``bindUserDn``
                    userSearchBase              String                  Required search base - defines where in the LDAP tree the UAA will search for a user
                    userSearchFilter            String                  Required user search filter used when searching for a user. {0} denotes the username in the search query.
                    groupSearchBase             String                  Required search base - defines where in the LDAP tree the UAA will search for user groups, use the value `memberOf` to skip group search, and use the memberOf attributes of the user.
                    groupSearchFilter           String                  Required Typically "memberOf={0}" group search filter used when searching for a group. {0} denotes the user DN in the search query, or the group DN in case of a nested group search.
                    mailAttributeName           String                  Required the name of the attribute that contains the user's email address. In most cases this is "mail"
                    mailSubstitute              String                  Optional If the user records do not contain an email address, the UAA can create one. It could be "{0}@this-default-was-not-configured.invalid" where
                    mailSubstituteOverridesLdap boolean                 Optional Set to true only if you always wish to override the LDAP supplied user email address
                    autoAddGroups               boolean                 Required Currently not used
                    groupSearchSubTree          boolean                 Required Should the sub tree be searched for user groups
                    groupMaxSearchDepth         int                     Required When searching for nested groups (groups within groups)
                    skipSSLVerification         boolean                 Optional Set to true if you wish to skip SSL certificate verification
                    emailDomain                 List<String>            Optional List of email domains associated with the LDAP provider for the purpose of associating users to the correct origin upon invitation. If null or empty list, no invitations are accepted. Wildcards supported.
                    attributeMappings           Map<String, Object>     Optional List of UAA attributes mapped to attributes from LDAP. Currently we support mapping given_name, family_name, email, phone_number and external_groups.
                    externalGroupsWhitelist     List<String>            Optional List of external groups (`DN` distinguished names`) that can be included in the ID Token if the `roles` scope is requested. See `UAA-LDAP.md UAA-LDAP.md`_ for more information
                    providerDescription         String                  Optional Human readable name/description of this provider

Curl Example      POST (Creating a SAML provider)::

                    curl -v -H"Authorization:Bearer $TOKEN" \
                      -XPOST \
                      -H"Accept:application/json" \
                      -H"Content-Type:application/json" \
                      -H"X-Identity-Zone-Id:testzone1" \
                      -d '{"originKey":"simplesamlphp","name":"simplesamlphp for testzone1","type":"saml","config":"{\"metaDataLocation\":\"<?xml version=\\\"1.0\\\"?>\\n<md:EntityDescriptor xmlns:md=\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\" xmlns:ds=\\\"http://www.w3.org/2000/09/xmldsig#\\\" entityID=\\\"http://example.com/saml2/idp/metadata.php\\\" ID=\\\"pfx06ad4153-c17c-d286-194c-dec30bb92796\\\"><ds:Signature>\\n  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\"/>\\n    <ds:SignatureMethod Algorithm=\\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\\"/>\\n  <ds:Reference URI=\\\"#pfx06ad4153-c17c-d286-194c-dec30bb92796\\\"><ds:Transforms><ds:Transform Algorithm=\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\"/><ds:Transform Algorithm=\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\"/></ds:Transforms><ds:DigestMethod Algorithm=\\\"http://www.w3.org/2000/09/xmldsig#sha1\\\"/><ds:DigestValue>begl1WVCsXSn7iHixtWPP8d/X+k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BmbKqA3A0oSLcn5jImz/l5WbpVXj+8JIpT/ENWjOjSd/gcAsZm1QvYg+RxYPBk+iV2bBxD+/yAE/w0wibsHrl0u9eDhoMRUJBUSmeyuN1lYzBuoVa08PdAGtb5cGm4DMQT5Rzakb1P0hhEPPEDDHgTTxop89LUu6xx97t2Q03Khy8mXEmBmNt2NlFxJPNt0FwHqLKOHRKBOE/+BpswlBocjOQKFsI9tG3TyjFC68mM2jo0fpUQCgj5ZfhzolvS7z7c6V201d9Tqig0/mMFFJLTN8WuZPavw22AJlMjsDY9my+4R9HKhK5U53DhcTeECs9fb4gd7p5BJy4vVp7tqqOg==</ds:SignatureValue>\\n<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\\n  <md:IDPSSODescriptor protocolSupportEnumeration=\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\">\\n    <md:KeyDescriptor use=\\\"signing\\\">\\n      <ds:KeyInfo xmlns:ds=\\\"http://www.w3.org/2000/09/xmldsig#\\\">\\n        <ds:X509Data>\\n          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\\n        </ds:X509Data>\\n      </ds:KeyInfo>\\n    </md:KeyDescriptor>\\n    <md:KeyDescriptor use=\\\"encryption\\\">\\n      <ds:KeyInfo xmlns:ds=\\\"http://www.w3.org/2000/09/xmldsig#\\\">\\n        <ds:X509Data>\\n          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\\n        </ds:X509Data>\\n      </ds:KeyInfo>\\n    </md:KeyDescriptor>\\n    <md:SingleLogoutService Binding=\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\" Location=\\\"http://example.com/saml2/idp/SingleLogoutService.php\\\"/>\\n    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\\n    <md:SingleSignOnService Binding=\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\" Location=\\\"http://example.com/saml2/idp/SSOService.php\\\"/>\\n  </md:IDPSSODescriptor>\\n  <md:ContactPerson contactType=\\\"technical\\\">\\n    <md:GivenName>Filip</md:GivenName>\\n    <md:SurName>Hanik</md:SurName>\\n    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\\n  </md:ContactPerson>\\n</md:EntityDescriptor>\",\"idpEntityAlias\":\"simplesamlphp\",\"zoneId\":\"testzone1\",\"nameID\":\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\",\"assertionConsumerIndex\":0,\"metadataTrustCheck\":false,\"showSamlLink\":true,\"socketFactoryClassName\":\"org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory\",\"linkText\":\"Login with TestZone1 Simple SAML PHP\",\"iconUrl\":null}","active":true,"identityZoneId":"testzone1"}' \
                      http://localhost:8080/uaa/identity-providers

Curl Example      POST (Creating a OAuth provider)::
                    curl -v -H"Authorization:Bearer $TOKEN" \
                      -XPOST \
                      -H"Accept:application/json" \
                      -H"Content-Type:application/json" \
                      -H"X-Identity-Zone-Id:testzone1" \
                      -d '{"originKey":"my-oauth-provider","name":"oauth-provider","type":"oauth","config":"{\"authUrl\":\"http://auth.url\",\"tokenUrl\":\"http://token.url\",\"tokenKey\":\"my-token-key\",\"alias\":\"oauth-idp-alias\",\"linkText\":\"My Oauth\",\"showLinkText\":true,\"skipSslValidation\":false,\"relyingPartyId\":\"my-uaa\",\"relyingPartySecret\":\"secret\"}"}' \
                      http://localhost:8080/uaa/identity-providers

Curl Example      POST (Creating an LDAP provider)::

                    curl -v -H"Authorization:Bearer $TOKEN" \
                      -XPOST -H"Accept:application/json" \
                      -H"Content-Type:application/json" \
                      -H"X-Identity-Zone-Id:testzone1" \
                      -d '{"originKey":"ldap","name":"myldap for testzone1","type":"ldap","config":"{\"baseUrl\":\"ldaps://localhost:33636\",\"skipSSLVerification\":true,\"bindUserDn\":\"cn=admin,ou=Users,dc=test,dc=com\",\"bindPassword\":\"adminsecret\",\"userSearchBase\":\"dc=test,dc=com\",\"userSearchFilter\":\"cn={0}\",\"groupSearchBase\":\"ou=scopes,dc=test,dc=com\",\"groupSearchFilter\":\"member={0}\",\"mailAttributeName\":\"mail\",\"mailSubstitute\":null,\"ldapProfileFile\":\"ldap/ldap-search-and-bind.xml\",\"ldapGroupFile\":\"ldap/ldap-groups-map-to-scopes.xml\",\"mailSubstituteOverridesLdap\":false,\"autoAddGroups\":true,\"groupSearchSubTree\":true,\"maxGroupSearchDepth\":10,\"emailDomain\":[\"example.com\",\"another.example.com\"]}",\"attributeMappings\":{"phone_number":"phone","given_name":"firstName","external_groups":"roles","family_name":"lastName","email":"email"},"externalGroupsWhitelist":["admin","user"],"active":true,"identityZoneId":"testzone1"}' \
                      http://localhost:8080/uaa/identity-providers

Curl Example      PUT (Updating a UAA provider)::

                    curl -v -H"Authorization:Bearer $TOKEN" \
                      -XPUT -H"Accept:application/json" \
                      -H"Content-Type:application/json" \
                      -H"X-Identity-Zone-Id:testzone1" \
                      -d '{"originKey":"uaa","name":"uaa","type":"uaa","config":"{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}"' \
                      http://localhost:8080/uaa/identity-providers/[identity_provider_id]


================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

Validating an Identity Provider
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Similar to how ``/identity-providers`` lets you create and update identity provider, an endpoint has been provided to test
your configuration prior to creating the provider. This test is performed in memory and all objects used to perform it are destroyed after the test has been completed.

The request is very similar to that of creating a provider, with the exception that you are also passing up username and password.
Note: **This only works for LDAP providers at the moment**

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``POST /identity-providers/test``
Header            ``X-Identity-Zone-Id`` (if using zones.<id>.admin scope against default UAA zone)
Scopes Required   ``zones.<zone id>.admin`` or ``idps.read`` and ``idps.write``
Request body      *example* (a provider contains the fields defined above) ::

                    {
                        "provider":{
                            "originKey":"ldap",
                            "name":"Test ldap provider",
                            "type":"ldap",
                            "config":"{\"baseUrl\":\"ldap://localhost:33389\",\"bindUserDn\":\"cn=admin,ou=Users,dc=test,dc=com\",\"bindPassword\":\"adminsecret\",\"userSearchBase\":\"dc=test,dc=com\",\"userSearchFilter\":\"cn={0}\",\"groupSearchBase\":\"ou=scopes,dc=test,dc=com\",\"groupSearchFilter\":\"member={0}\",\"mailAttributeName\":\"mail\",\"mailSubstitute\":null,\"ldapProfileFile\":\"ldap/ldap-search-and-bind.xml\",\"ldapGroupFile\":\"ldap/ldap-groups-map-to-scopes.xml\",\"mailSubstituteOverridesLdap\":false,\"autoAddGroups\":true,\"groupSearchSubTree\":true,\"maxGroupSearchDepth\":10}",
                            "active":true,
                            "identityZoneId":"testzone1"
                        },
                        "credentials":{
                            "username":"marissa2",
                            "password":"ldap"
                        }
                    }


Response body     *example* ::

                    HTTP/1.1 200 OK
                    Content-Type: application/json

                    "ok"

* Response        *Codes* ::

                    200 - Ok - Successful authentication
                    417 - Expectation Failed - Bad credentials
                    400 - Bad Request - Invalid configuration - result contains stack trace
                    403 - Forbidden - insufficient scope
                    500 - Internal Server Error - error information will only be in server logs


Curl Example      POST (Testing an LDAP provider)::

                    curl -v -H"Authorization:Bearer $TOKEN" \
                      -XPOST -H"Accept:application/json" \
                      -H"Content-Type:application/json" \
                      -H"X-Identity-Zone-Id:testzone1" \
                      -d '{"provider":{"id":null,"originKey":"ldap","name":"Test ldap provider","type":"ldap","config":"{\"baseUrl\":\"ldap://localhost:33389\",\"bindUserDn\":\"cn=admin,ou=Users,dc=test,dc=com\",\"bindPassword\":\"adminsecret\",\"userSearchBase\":\"dc=test,dc=com\",\"userSearchFilter\":\"cn={0}\",\"groupSearchBase\":\"ou=scopes,dc=test,dc=com\",\"groupSearchFilter\":\"member={0}\",\"mailAttributeName\":\"mail\",\"mailSubstitute\":null,\"ldapProfileFile\":\"ldap/ldap-search-and-bind.xml\",\"ldapGroupFile\":\"ldap/ldap-groups-map-to-scopes.xml\",\"mailSubstituteOverridesLdap\":false,\"autoAddGroups\":true,\"groupSearchSubTree\":true,\"maxGroupSearchDepth\":10}","version":0,"created":1427829319730,"active":true,"identityZoneId":"testzone1","last_modified":1427829319730},"credentials":{"username":"marissa2","password":"ldap"}}' \
                      http://localhost:8080/uaa/identity-providers/test

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

Deleting an Identity Provider
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deleting an identity provider does a hard delete. The identity provider and all related records will be deleted.

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``DELETE /identity-providers/<identity provider id>``
Header            ``X-Identity-Zone-Id`` (if using zones.<id>.admin scope against default UAA zone)
Scopes Required   ``zones.<zone id>.admin`` or ``idps.write``
Response body      *example* (a provider contains the fields defined above) ::

                    {
                        "provider":{
                            "originKey":"ldap",
                            "name":"Test ldap provider",
                            "type":"ldap",
                            "config":"{\"baseUrl\":\"ldap://localhost:33389\",\"bindUserDn\":\"cn=admin,ou=Users,dc=test,dc=com\",\"bindPassword\":\"adminsecret\",\"userSearchBase\":\"dc=test,dc=com\",\"userSearchFilter\":\"cn={0}\",\"groupSearchBase\":\"ou=scopes,dc=test,dc=com\",\"groupSearchFilter\":\"member={0}\",\"mailAttributeName\":\"mail\",\"mailSubstitute\":null,\"ldapProfileFile\":\"ldap/ldap-search-and-bind.xml\",\"ldapGroupFile\":\"ldap/ldap-groups-map-to-scopes.xml\",\"mailSubstituteOverridesLdap\":false,\"autoAddGroups\":true,\"groupSearchSubTree\":true,\"maxGroupSearchDepth\":10}",
                            "active":true,
                            "identityZoneId":"testzone1"
                        }
                    }

* Response        *Codes* ::

                    200 - Ok - Successful authentication
                    404 - Not Found - Invalid provider ID
                    400 - Bad Request - Invalid configuration - result contains stack trace
                    403 - Forbidden - insufficient scope
                    500 - Internal Server Error - error information will only be in server logs

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================


User Account Management APIs
============================

UAA supports the `SCIM <http://simplecloud.info>`_ standard for
these APIs and endpoints.  These endpoints are themselves secured by OAuth2, and access decision is done based on the 'scope' and 'aud' fields of the JWT OAuth2 token.

Create a User: ``POST /Users``
------------------------------

See `SCIM - Creating Resources`__

__ http://www.simplecloud.info/specs/draft-scim-api-01.html#create-resource

New users are automatically verified by default.  Unverified users can be created by specifying their `verified: false` property in the request body of the `POST` to `/Users`, as shown in the example below. Unverified users must then go through the verification process. Obtaining a verification link (to send to the user) is outlined in the section `Verify User Links: GET /Users/{id}/verify-link`_. Users may then use this link to complete the verification process, at which point they'll be able to login.

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``POST /Users``
Header            Authorization Bearer token
Scopes Required   scim.write or scim.create
Request body      *example*  ::

                    {
                        "externalId":"",
                        "userName":"JOE_tpcqlm",
                        "name": {
                            "formatted":"Joe User",
                            "familyName":"User",
                            "givenName":"Joe"
                        },
                        "emails":[{"value":"joe@blah.com"}],
                        "active":true,
                        "verified":false,
                        "origin":"uaa",
                        "schemas":["urn:scim:schemas:core:1.0"]}


                    The ``userName`` / ``origin`` combination is unique in the UAA, but is allowed to change.  Each user also has a fixed primary key which is a UUID (stored in the ``id`` field of the core schema).

Response Body     *example* ::

                    HTTP/1.1 201 Created
                    Content-Type: application/json
                    Location: https://example.com/Users/c72518a7-8f68-4de6-b9b7-22a14292ef3f
                    ETag: "0"

                    {
                        "id":"c72518a7-8f68-4de6-b9b7-22a14292ef3f",
                        "meta":{"version":0,"created":"2015-04-01T11:42:59.420Z","lastModified":"2015-04-01T11:42:59.420Z"},
                        "userName":"JOE_tpcqlm",
                        "name":{
                            "familyName":"User",
                            "givenName":"Joe"
                        },
                        "emails":[{"value":"joe@blah.com"}],
                        "groups":[
                            {"value":"e3087175-49d7-416f-829a-dd5c45d81e57","display":"password.write","type":"DIRECT"},
                            {"value":"cac347d6-e1d2-4f7f-ac7a-3e915fd395cc","display":"oauth.approvals","type":"DIRECT"},
                            {"value":"8373425c-df35-4e6a-ac50-36fc4287ad7e","display":"cloud_controller.read","type":"DIRECT"},
                            {"value":"a000dba5-81f9-4f4f-b73a-15d03d3958a9","display":"approvals.me","type":"DIRECT"},
                            {"value":"d479a26a-090a-45ce-b0cf-a0eb9a28ba93","display":"scim.me","type":"DIRECT"},
                            {"value":"ad228b94-a553-4122-a111-31eb9970c050","display":"scim.userids","type":"DIRECT"},
                            {"value":"2c90cc32-15f9-4c10-8926-b99688324ae6","display":"cloud_controller.write","type":"DIRECT"},
                            {"value":"395d8a63-190e-4152-baf4-26c830e6d3c4","display":"uaa.user","type":"DIRECT"},
                            {"value":"1b27d514-8179-41fb-80e9-057b1d88c6d0","display":"openid","type":"DIRECT"},
                            {"value":"7db41ba4-b503-43a4-9c5f-b57d840176b6","display":"cloud_controller_service_permissions.read","type":"DIRECT"}
                        ],
                        "approvals":[],
                        "active":true,
                        "verified":false,
                        "origin":"uaa",
                        "zoneId":"uaa",
                        "schemas":["urn:scim:schemas:core:1.0"]
                    }

Response Codes    *example* ::

                    201 - Created successfully
                    400 - Bad Request - unparseable, syntactically incorrect etc
                    401 - Unauthorized - Invalid token
                    403 - Forbidden - insufficient scope


Fields            *Available Fields* ::

                    User Fields
                    ======================  ===============  ======== =======================================================
                    id                      String(36)       Auto     Unique identifier for this provider - GUID generated by the UAA
                    userName                String(255)      Required Username, typically an email address
                    name                    Map              Optional Map containing the fields
                      givenName             String           Optional First name
                      familyName            String           Optional Last name
                    emails                  List<String>     Required List of email addresses, currently only one is supported
                    active                  boolean          Required Set to true to allow this user to login
                    verified                boolean          Required Set to true to indicate that this user has been verified.
                    origin                  String           Optional Set the origin of this user. If empty default of 'uaa' will be set
                    schemas                 List<String>     Optional Singleton list of 'urn:scim:schemas:core:1.0'
                    externalId              String           Optional If this user has an external ID in another system

Curl Example      POST Create a user::

                    curl -v
                      -H"Authorization: Bearer $TOKEN"
                      -XPOST -H"Accept:application/json"
                      -H"Content-Type:application/json"
                      --data '{"userName":"JOE_tpcqlm","name":{"formatted":"Joe User","familyName":"User","givenName":"Joe"},"emails":[{"value":"joe@blah.com"}]}'
                      http://localhost:8080/uaa/Users

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

Update a User: ``PUT /Users/{id}``
----------------------------------

See `SCIM - Modifying with PUT <http://www.simplecloud.info/specs/draft-scim-api-01.html#edit-resource-with-put>`_


================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``PUT /Users/{id}``
Header            Authorization Bearer token
Header            If-Match with the value of the current version of the user, or * to disable version check
Scopes Required   scim.write or the user id in the token is {id}
Request body      *example*  ::

                    {
                        "externalId":"",
                        "userName":"JOE_tpcqlm",
                        "name": {
                            "formatted":"Joe User",
                            "familyName":"User",
                            "givenName":"Joe"
                        },
                        "emails":[{"value":"joe@blah.com"}],
                        "active":true,
                        "verified":false,
                        "origin":"uaa",
                        "schemas":["urn:scim:schemas:core:1.0"]}



Response Body     *example* ::

                    HTTP/1.1 200 Ok
                    Content-Type: application/json
                    Location: https://example.com/Users/c72518a7-8f68-4de6-b9b7-22a14292ef3f
                    ETag: "1"

                    {
                        "id":"c72518a7-8f68-4de6-b9b7-22a14292ef3f",
                        "meta":{"version":0,"created":"2015-04-01T11:42:59.420Z","lastModified":"2015-04-01T11:42:59.420Z"},
                        "userName":"JOE_tpcqlm",
                        "name":{
                            "familyName":"User",
                            "givenName":"Joe"
                        },
                        "emails":[{"value":"joe@blah.com"}],
                        "groups":[
                            {"value":"e3087175-49d7-416f-829a-dd5c45d81e57","display":"password.write","type":"DIRECT"},
                            {"value":"cac347d6-e1d2-4f7f-ac7a-3e915fd395cc","display":"oauth.approvals","type":"DIRECT"},
                            {"value":"8373425c-df35-4e6a-ac50-36fc4287ad7e","display":"cloud_controller.read","type":"DIRECT"},
                            {"value":"a000dba5-81f9-4f4f-b73a-15d03d3958a9","display":"approvals.me","type":"DIRECT"},
                            {"value":"d479a26a-090a-45ce-b0cf-a0eb9a28ba93","display":"scim.me","type":"DIRECT"},
                            {"value":"ad228b94-a553-4122-a111-31eb9970c050","display":"scim.userids","type":"DIRECT"},
                            {"value":"2c90cc32-15f9-4c10-8926-b99688324ae6","display":"cloud_controller.write","type":"DIRECT"},
                            {"value":"395d8a63-190e-4152-baf4-26c830e6d3c4","display":"uaa.user","type":"DIRECT"},
                            {"value":"1b27d514-8179-41fb-80e9-057b1d88c6d0","display":"openid","type":"DIRECT"},
                            {"value":"7db41ba4-b503-43a4-9c5f-b57d840176b6","display":"cloud_controller_service_permissions.read","type":"DIRECT"}
                        ],
                        "approvals":[],
                        "active":true,
                        "verified":false,
                        "origin":"uaa",
                        "zoneId":"uaa",
                        "schemas":["urn:scim:schemas:core:1.0"]
                    }

Response Codes    *example* ::

                    201 - Created successfully
                    400 - Bad Request - unparseable, syntactically incorrect etc
                    401 - Unauthorized - Invalid token
                    403 - Forbidden - insufficient scope
                    404 - Not Found - non existent ID
                    409 - Conflict - If-Match header, version mismatch


Fields            *Available Fields* ::

                    User Fields
                    ======================  ===============  ======== =======================================================
                    id                      String(36)       Auto     Unique identifier for this provider - GUID generated by the UAA
                    userName                String(255)      Required Username, typically an email address
                    name                    Map              Optional Map containing the fields
                      givenName             String           Optional First name
                      familyName            String           Optional Last name
                    emails                  List<String>     Required List of email addresses, currently only one is supported
                    active                  boolean          Required Set to true to allow this user to login
                    verified                boolean          Required Set to true to indicate that this user has been verified.
                    origin                  String           Optional Set the origin of this user. If empty default of 'uaa' will be set
                    schemas                 List<String>     Optional Singleton list of 'urn:scim:schemas:core:1.0'
                    externalId              String           Optional If this user has an external ID in another system

Curl Example      PUT Create a user::

                    curl -v
                      -H"If-Match:*"
                      -H"Authorization: Bearer $TOKEN"
                      -XPUT
                      -H"Accept:application/json"
                      -H"Content-Type:application/json"
                      --data '{"userName":"JOE_tpcqlsm","name":{"formatted":"Joe User","familyName":"User","givenName":"Joe"},"emails":[{"value":"joe@blah.com"}]}'
                      http://localhost:8080/uaa/Users/24c1c1a9-9b30-4eaa-b8e3-d2e1aabf1dc7

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

Partially Update a User: ``PATCH /Users/{id}``
----------------------------------

See `SCIM - Modifying with PATCH <http://www.simplecloud.info/specs/draft-scim-api-01.html#edit-resource-with-patch>`_


================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``PATCH /Users/{id}``
Header            Authorization Bearer token
Header            If-Match with the value of the current version of the user, or * to disable version check
Scopes Required   scim.write or the user id in the token is {id}
Request body      *example*  ::

                    {
                        "name": {
                            "formatted":"Joe User",
                            "familyName":"User",
                            "givenName":"Joe"
                        },
                        "schemas":["urn:scim:schemas:core:1.0"]}



Response Body     *example* ::

                    HTTP/1.1 200 Ok
                    Content-Type: application/json
                    Location: https://example.com/Users/c72518a7-8f68-4de6-b9b7-22a14292ef3f
                    ETag: "1"

                    {
                        "id":"c72518a7-8f68-4de6-b9b7-22a14292ef3f",
                        "meta":{"version":0,"created":"2015-04-01T11:42:59.420Z","lastModified":"2015-04-01T11:42:59.420Z"},
                        "userName":"JOE_tpcqlm",
                        "name":{
                            "familyName":"User",
                            "givenName":"Joe"
                        },
                        "emails":[{"value":"joe@blah.com"}],
                        "groups":[
                            {"value":"e3087175-49d7-416f-829a-dd5c45d81e57","display":"password.write","type":"DIRECT"},
                            {"value":"cac347d6-e1d2-4f7f-ac7a-3e915fd395cc","display":"oauth.approvals","type":"DIRECT"},
                            {"value":"8373425c-df35-4e6a-ac50-36fc4287ad7e","display":"cloud_controller.read","type":"DIRECT"},
                            {"value":"a000dba5-81f9-4f4f-b73a-15d03d3958a9","display":"approvals.me","type":"DIRECT"},
                            {"value":"d479a26a-090a-45ce-b0cf-a0eb9a28ba93","display":"scim.me","type":"DIRECT"},
                            {"value":"ad228b94-a553-4122-a111-31eb9970c050","display":"scim.userids","type":"DIRECT"},
                            {"value":"2c90cc32-15f9-4c10-8926-b99688324ae6","display":"cloud_controller.write","type":"DIRECT"},
                            {"value":"395d8a63-190e-4152-baf4-26c830e6d3c4","display":"uaa.user","type":"DIRECT"},
                            {"value":"1b27d514-8179-41fb-80e9-057b1d88c6d0","display":"openid","type":"DIRECT"},
                            {"value":"7db41ba4-b503-43a4-9c5f-b57d840176b6","display":"cloud_controller_service_permissions.read","type":"DIRECT"}
                        ],
                        "approvals":[],
                        "active":true,
                        "verified":false,
                        "origin":"uaa",
                        "zoneId":"uaa",
                        "schemas":["urn:scim:schemas:core:1.0"]
                    }

Response Codes    *example* ::

                    201 - Created successfully
                    400 - Bad Request - unparseable, syntactically incorrect etc
                    401 - Unauthorized - Invalid token
                    403 - Forbidden - insufficient scope
                    404 - Not Found - non existent ID
                    409 - Conflict - If-Match header, version mismatch


Fields            *Available Fields* ::

                    User Fields
                    ======================  ===============  ======== =======================================================
                    id                      String(36)       Auto     Unique identifier for this provider - GUID generated by the UAA
                    userName                String(255)      Optional Username, typically an email address
                    name                    Map              Optional Map containing the fields
                      givenName             String           Optional First name
                      familyName            String           Optional Last name
                    emails                  List<String>     Optional List of email addresses, currently only one is supported
                    active                  boolean          Optional Set to true to allow this user to login
                    verified                boolean          Optional Set to true to indicate that this user has been verified.
                    origin                  String           Optional Set the origin of this user. If empty default of 'uaa' will be set
                    schemas                 List<String>     Optional Singleton list of 'urn:scim:schemas:core:1.0'
                    externalId              String           Optional If this user has an external ID in another system
                    meta.attributes         String[]         Optional List of attributes, whose values shall be deleted

Curl Example      PATCH Update a user::

                    curl -v
                      -H"If-Match:*"
                      -H"Authorization: Bearer $TOKEN"
                      -XPATCH
                      -H"Accept:application/json"
                      -H"Content-Type:application/json"
                      --data '{"name":{"formatted":"Joe User","familyName":"User","givenName":"Joe"}}'
                      http://localhost:8080/uaa/Users/24c1c1a9-9b30-4eaa-b8e3-d2e1aabf1dc7

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================


Delete a User: ``DELETE /Users/{id}``
-------------------------------------

The UAA has two modes of deleting a user. Either a hard delete, or setting ``active=false``
This behavior is controlled by the boolean property ``scim.delete.deactivate``

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``DELETE /Users/{id}``
Header            Authorization Bearer token
Header            If-Match with the value of the current version of the user, or * to disable version check
Scopes Required   scim.write

Response Body     *example* ::

                    HTTP/1.1 200 Ok
                    Content-Type: application/json
                    Location: https://example.com/Users/c72518a7-8f68-4de6-b9b7-22a14292ef3f
                    ETag: "2"

                    {
                        "id":"c72518a7-8f68-4de6-b9b7-22a14292ef3f",
                        "meta":{"version":0,"created":"2015-04-01T11:42:59.420Z","lastModified":"2015-04-01T11:42:59.420Z"},
                        "userName":"JOE_tpcqlm",
                        "name":{
                            "familyName":"User",
                            "givenName":"Joe"
                        },
                        "emails":[{"value":"joe@blah.com"}],
                        "groups":[
                            {"value":"e3087175-49d7-416f-829a-dd5c45d81e57","display":"password.write","type":"DIRECT"},
                            {"value":"cac347d6-e1d2-4f7f-ac7a-3e915fd395cc","display":"oauth.approvals","type":"DIRECT"},
                            {"value":"8373425c-df35-4e6a-ac50-36fc4287ad7e","display":"cloud_controller.read","type":"DIRECT"},
                            {"value":"a000dba5-81f9-4f4f-b73a-15d03d3958a9","display":"approvals.me","type":"DIRECT"},
                            {"value":"d479a26a-090a-45ce-b0cf-a0eb9a28ba93","display":"scim.me","type":"DIRECT"},
                            {"value":"ad228b94-a553-4122-a111-31eb9970c050","display":"scim.userids","type":"DIRECT"},
                            {"value":"2c90cc32-15f9-4c10-8926-b99688324ae6","display":"cloud_controller.write","type":"DIRECT"},
                            {"value":"395d8a63-190e-4152-baf4-26c830e6d3c4","display":"uaa.user","type":"DIRECT"},
                            {"value":"1b27d514-8179-41fb-80e9-057b1d88c6d0","display":"openid","type":"DIRECT"},
                            {"value":"7db41ba4-b503-43a4-9c5f-b57d840176b6","display":"cloud_controller_service_permissions.read","type":"DIRECT"}
                        ],
                        "approvals":[],
                        "active":true,
                        "verified":false,
                        "origin":"uaa",
                        "zoneId":"uaa",
                        "schemas":["urn:scim:schemas:core:1.0"]
                    }

Response Codes    *example* ::

                    200 - Ok success
                    401 - Unauthorized - Invalid token
                    403 - Forbidden - insufficient scope
                    404 - Not Found - non existent ID


Curl Example      DELETE Delete a user::

                    curl -v
                      -H"If-Match:*"
                      -H"Authorization: Bearer $TOKEN"
                      -XDELETE
                      -H"Accept:application/json"
                      http://localhost:8080/uaa/Users/24c1c1a9-9b30-4eaa-b8e3-d2e1aabf1dc7

================  ==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================


Change Password: ``PUT /Users/{id}/password``
---------------------------------------------

See `SCIM - Changing Password <http://www.simplecloud.info/specs/draft-scim-api-01.html#change-password>`_

* Request: ``PUT /Users/{id}/password``
* Authorization: Authorization header containing an `OAuth2`_ bearer token with::

        scope = password.write
        aud = password

  OR ::

        user_id = {id} i.e id of the user whose password is being updated

* Request::

        Authorization: Bearer URh3jpUFIvZ96G9o
        Content-Type: application/json
        Accept: application/json

        {
            "schemas":["urn:scim:schemas:core:1.0"],
            "oldPassword":"secr3T",
            "password":"n3wAw3som3Passwd"
        }

* Response::

        HTTP/1.1 200 OK
        Content-Type: application/json

        {
            "status":"ok",
            "message":"password updated"
        }

* Response Codes::

        200 - Updated successfully
        400 - Bad Request
        401 - Unauthorized
        404 - Not found

* Example CURL ::

        $ curl 'http://localhost:8080/Users/a9717027-b838-40bd-baca-b9f9d38a440d/password' -i -X PUT -H 'Authorization: Bearer tURh3jpUFIvZ96G9o' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"oldPassword":"secr3T","password":"n3wAw3som3Passwd"}'

.. note:: SCIM specifies that a password change is a PATCH, but since this isn't supported by many clients, we have used PUT.  SCIM offers the option to use POST with a header override - if clients want to send `X-HTTP-Method-Override` they can ask us to add support for that.

Reset Password Flow:
----------------------
1. Retrieve verification ``code`` from ``/password_resets`` endpoint.
2. Include ``code`` and ``new_password`` in body of call to ``/password_change`` endpoint to complete the password reset.

``POST /password_resets``
~~~~~~~~~~~~~~~~~~~~~~~~~

* Request: ``POST /password_resets``

* Authorization: Authorization header containing an `OAuth2`_ bearer token with::

        scope = oauth.login

* Request Parameters::

        client_id; the id of the client requesting the password reset (optional)
        redirect_uri; the eventual URI that will be redirected after the user finishes resetting their password (optional)
                      the redirect_uri whitelist that can be set per client accepts wildcards, and matches against this redirect_uri using Ant-style path pattern matching (as per <http://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/util/AntPathMatcher.html>)

* Request Body::

        Authorization: Bearer URh3jpUFIvZ96G9o
        Content-Type: application/json

        example@email.com       // username of user for whom to reset password

* Response::

        HTTP/1.1 201 Created
        Content-Type: application/json

        {
            "code":"1yw7VS",
            "user_id":"d6aa012a-b7bb-4dea-9128-3586f9c3d738"
        }

* Response Codes::

        201 - Created
        400 - Bad Request
        401 - Unauthorized
        403 - Forbidden
        404 - Not found
        409 - Conflict

* Example CURL ::

        $ curl 'http://localhost:8080/password_resets' -i -X POST -H 'Content-Type: application/json' -d example@email.com


``POST /password_change``
~~~~~~~~~~~~~~~~~~~~~~~~~

* Request: ``POST /password_change``

* Authorization: Authorization header containing an `OAuth2`_ bearer token with::

        scope = oauth.login

* Request Body::

        Authorization: Bearer URh3jpUFIvZ96G9o
        Content-Type: application/json

        {
            "code":"1yw7VS",
            "new_password":"new-password"
        }

* Response::

        HTTP/1.1 200 OK
        Content-Type: application/json

        {
            "username": "example",
            "email": "example@email.com",
            "code": "OFoEP8", // autologin code
            "user_id": "d6aa012a-b7bb-4dea-9128-3586f9c3d738"
        }

* Response Codes::

        200 - OK
        400 - Bad Request
        401 - Unauthorized
        403 - Forbidden
        404 - Not found

* Example CURL ::

        $ curl 'http://localhost:8080/password_change' -i -X POST -H 'Content-Type: application/json' -d '{"code":"1yw7VS","new_password":"example-password"}'


Change Email Flow:
----------------------
1. Retrieve verification ``code`` from ``/email_verifications`` endpoint.
2. Include ``code`` in body of call to ``/email_changes`` endpoint to complete the email change.

``POST /email_verifications``
~~~~~~~~~~~~~~~~~~~~~~~~~

* Request: ``POST /email_verifications``

* Authorization: Authorization header containing an `OAuth2`_ bearer token with::

        scope = oauth.login

* Request Body::

        Authorization: Bearer URh3jpUFIvZ96G9o
        Content-Type: application/json

        {
            "userId":"d6aa012a-b7bb-4dea-9128-3586f9c3d738",
            "email":"example@newemail.com",
            "client_id":"some_client"
        }

* Response::

        HTTP/1.1 201 Created
        Content-Type: application/json

        6FfI4o       // verification code

* Response Codes::

        201 - Created
        400 - Bad Request
        401 - Unauthorized
        403 - Forbidden
        404 - Not found
        409 - Conflict

* Example CURL ::

        $ curl 'http://localhost:8080/email_verifications' -i -X POST -H 'Content-Type: application/json' -d '{"userId":"d6aa012a-b7bb-4dea-9128-3586f9c3d738","email":"example@newemail.com","client_id":"some_client"}'


``POST /email_changes``
~~~~~~~~~~~~~~~~~~~~~~~~~

* Request: ``POST /email_changes``

* Authorization: Authorization header containing an `OAuth2`_ bearer token with::

        scope = oauth.login

* Request Body::

        Authorization: Bearer URh3jpUFIvZ96G9o
        Content-Type: application/json

        6FfI4o       // verification code

* Response::

        HTTP/1.1 200 OK
        Content-Type: application/json

        {
            "username": "example",
            "userId": "d6aa012a-b7bb-4dea-9128-3586f9c3d738",
            "redirect_url": "preregistered.redirect/url",
            "email": "example@newemail.com"
        }

* Response Codes::

        200 - OK
        400 - Bad Request
        401 - Unauthorized
        403 - Forbidden

* Example CURL ::

        $ curl 'http://localhost:8080/email_changes' -i -X POST -H 'Content-Type: application/json' -d 6FfI4o


Verify User Links: ``GET /Users/{id}/verify-link``
--------------------------------------------------


* Request: ``GET /Users/{id}/verify-link``

* Request Parameters::

        client_id; the id of the client requesting the verification link (optional)
        redirect_uri; the eventual URI that will be redirected after the user finishes resetting their password (optional)
                      the redirect_uri whitelist that can be set per client accepts wildcards, and matches against this redirect_uri using Ant-style path pattern matching (as per <http://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/util/AntPathMatcher.html>)

* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.create

* Request Body::

        Host: example.com
        Accept: application/json
        Authorization: Bearer h480djs93hd8

* Response Body::

        {
          "verify_link": "http://myuaa.cloudfoundry.com/verify_user?code=yuT6rd"
        }

* Response Codes::

        200 - Success
        400 - Bad Request
        401 - Unauthorized
        403 - Forbidden
        404 - Not Found; Scim Resource Not Found
        405 - Method Not Allowed; User Already Verified

Verify User: ``GET /Users/{id}/verify``
---------------------------------------


* Request: ``GET /Users/{id}/verify``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

  OR ::

        user_id = {id} i.e id of the user whose verify status is being set to true

* Request Body::

        Host: example.com
        Accept: application/json
        Authorization: Bearer h480djs93hd8


* Response Body: the updated details

* Response Codes::

        200 - Updated successfully
        400 - Bad Request
        401 - Unauthorized
        404 - Not found

Query for Information: ``GET /Users``
---------------------------------------

See `SCIM - List/Query Resources`__

__ http://www.simplecloud.info/specs/draft-scim-api-01.html#query-resources

Get information about a user. This is needed by to convert names and email addresses to immutable ids, and immutable ids to display names. The implementation provides the core schema from the specification, but not all attributes are handled in the back end at present (e.g. only one email address per account).

Filters: note that, per the specification, attribute values are comma separated and the filter expressions can be combined with boolean keywords ("or" and "and").

* Request: ``GET /Users?attributes={requestedAttributes}&filter={filter}``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.read
        aud = scim

* Response Body (for ``GET /Users?attributes=id&filter=emails.value eq 'bjensen@example.com'``)::

        HTTP/1.1 200 OK
        Content-Type: application/json

        {
          "totalResults":1,
          "schemas":["urn:scim:schemas:core:1.0"],
          "resources":[
            {
              "id":"123456"
            }
          ]
        }

Query for the existence of a specific username.

* Response Body (for ``GET /Users?attributes=userName&filter=userName eq 'bjensen'``)::

    HTTP/1.1 200 OK
        Content-Type: application/json

        {
          "resources": [
            {
              "userName": "bjensen"
            }
          ],
          "startIndex": 1,
          "itemsPerPage": 100,
          "totalResults": 1,
          "schemas":["urn:scim:schemas:core:1.0"]
    }


* Response Codes::

        200 - Success
        400 - Bad Request
        401 - Unauthorized

Delete a User: ``DELETE /Users/{id}``
-------------------------------------

See `SCIM - Deleting Resources <http://www.simplecloud.info/specs/draft-scim-api-01.html#delete-resource>`_.

* Request: ``DELETE /Users/{id}``
* Request Headers:

  + Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

  + ``If-Match`` the ``ETag`` (version id) for the value to delete

* Request Body: Empty
* Response Body: Empty
* Response Codes::

        200 - Success
        401 - Unauthorized
        404 - Not found

Deleting accounts is handled in the back end logically using the `active` flag, so to see a list of deleted users you can filter on that attribute (filters by default have it set to true), e.g.

* Request: ``GET /Users?attributes=id,userName&filter=userName co 'bjensen' and active eq false``
* Response Body: list of users matching the filter

Converting UserIds to Names
---------------------------

There is a SCIM-like endpoint for converting usernames to names, with the same filter and attribute syntax as ``/Users``. It must be supplied with a ``filter`` parameter.  It is a special purpose endpoint for use as a user id/name translation api, and is should be disabled in production sites by setting ``scim.userids_enabled=false`` in the UAA configuration. It will be used by cf so it has to be quite restricted in function (i.e. it's not a general purpose groups or users endpoint). Otherwise the API is the same as /Users.
This endpoint has a few restrictions, the only two fields that are allowed for filtering are ``id`` and ``userName`` and the only valid filter operator is the ``eq`` operator.
Wildcard searches such as ``sw`` or ``co`` are not allowed. This endpoint requires the scope ``scim.userids`` to be present in the token.

* Request: ``GET /ids/Users``
* Response Body: list of users matching the filter ::

    {
        "itemsPerPage": 100,
        "resources": [
            {
                "id": "309cc3b7-ec9a-4180-9ba1-5d73f12e97ea",
                "origin": "uaa",
                "userName": "marissa"
            }
        ],
        "schemas": [
            "urn:scim:schemas:core:1.0"
        ],
        "startIndex": 1,
        "totalResults": 1
    }




Inviting Users
--------------

The UAA supports the notion of inviting users. When a user is invited by providing an email address, the system will
locate the appropriate authentication provider and create the user account.
The invitation endpoint then returns the corresponding `user_id` and `inviteLink`.
Batch processing is allowed by specifying more than one email address.
The endpoint takes two parameters, a client_id (optional) and a redirect_uri.
When a user accepts the invitation, the user will be redirected to the redirect_uri.
The redirect_uri will be validated against allowed redirect_uri for the client.

* Request: ``POST /invite_users`` ::

    client_id=<some_client>&redirect_uri=http://redirect.here.after.accept

    {
        "emails": [
            {
                "user1@domain1.com",
                "user2@domain2.com",
                "user3@domain2.com"
            }
        ]
    }

* Response Body: list of users matching the filter ::

    {
        "new_invites":[
            {"email":"user1@cqv4f7.com","userId":"38de0ac4-b194-4e33-b6c2-0755a37205fb","origin":"uaa","success":true,"inviteLink":"http://myuaa.cloudfoundry.com/invitations/accept?code=yuT6rd","errorCode":null,"errorMessage":null},
            {"email":"user2@cqv4f7.com","userId":"1665631f-1957-44fe-ac49-2739dd55bb3f","origin":"uaa","success":true,"inviteLink":"http://myuaa.cloudfoundry.com/invitations/accept?code=yuT6rd","errorCode":null,"errorMessage":null}
        ],
        "failed_invites":[]
    }



Group Management APIs
=====================
In addition to SCIM users, UAA also supports/implements SCIM_groups_ for managing group-membership of users. These endpoints too are secured by OAuth2 bearer tokens.

.. _SCIM_groups: http://tools.ietf.org/html/draft-ietf-scim-core-schema-00#section-8

Create a Group: ``POST /Groups``
--------------------------------

See `SCIM - Creating Resources`__

__ http://www.simplecloud.info/specs/draft-scim-api-01.html#create-resource

* Request: ``POST /Groups``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

* Request Body::

        {
          "displayName":"uaa.admin",
          "members":[
            { "type":"USER","authorities":["READ"],"value":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f","origin":"uaa" }
          ],
          "description":"A description for the group"
        }


The ``displayName`` is unique in the UAA, but is allowed to change.  Each group also has a fixed primary key which is a UUID (stored in the ``id`` field of the core schema).
The origin value shows what identity provider was responsible for making the connection between the user and the group. For example, if this
relationship came from an LDAP user, it would have origin=ldap. The ``description`` is optional and will appear when the user is asked to approve groups for clients.

* Response Body::

        HTTP/1.1 201 Created
        Content-Type: application/json
        Location: https://example.com/v1/Groups/uid=123456
        ETag: "0"

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "id":"123456",
          "meta":{
            "version":0,
            "created":"2011-08-01T21:32:44.882Z",
            "lastModified":"2011-08-01T21:32:44.882Z"
          },
          "displayName":"uaa.admin",
          "members":[
          { "type":"USER","authorities":["READ"],"value":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f","origin":"uaa" }
          ]
        }

* Response Codes::

        201 - Created successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized

The members.value sub-attributes MUST refer to a valid SCIM resource id in the UAA, i.e the UUID of an existing SCIM user or group.

Update a Group: ``PUT /Groups/{id}``
------------------------------------

See `SCIM - Modifying with PUT <http://www.simplecloud.info/specs/draft-scim-api-01.html#edit-resource-with-put>`_

* Request: ``PUT /Groups/{id}``
* Request Headers:

  + Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write OR groups.update
        aud = scim

    OR ::

        user_id = <id of a user who is an admin member of the group being updated>
        + (optional) ``If-Match`` the ``ETag`` (version id) for the value to update

* Request Body::

        Host: example.com
        Accept: application/json
        Authorization: Bearer h480djs93hd8
        If-Match: "2"

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "id":"123456",
          "displayName":"uaa.admin",
          "meta":{
            "version":2,
            "created":"2011-11-30T21:11:30.000Z",
            "lastModified":"2011-12-30T21:11:30.000Z"
          },
          "members":[
             {"type":"USER","authorities":["READ"],"value":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f","origin":"uaa"},
             {"type":"USER","authorities":["READ", "WRITE"],"value":"40c44bda-8b70-f771-74a2-3ebe4bda40c4","origin":"uaa"}
          ],
          "description": "A new description"
        }

* Response Body:
        As for create operation, returns the entire, updated record, with the Location header pointing to the resource.

* Response Codes::

        200 - Updated successfully
        400 - Bad Request
        401 - Unauthorized
        404 - Not found

As with the create operation, members.value sub-attributes MUST refer to a valid SCIM resource id in the UAA, i.e the UUID of a an existing SCIM user or group.

Partially Update a Group: ``PATCH /Groups/{id}``
------------------------------------

See `SCIM - Modifying with PATCH <http://www.simplecloud.info/specs/draft-scim-api-01.html#edit-resource-with-patch>`_

* Request: ``PATCH /Groups/{id}``
* Request Headers:

  + Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write OR groups.update
        aud = scim

    OR ::

        user_id = <id of a user who is an admin member of the group being updated>
        + (optional) ``If-Match`` the ``ETag`` (version id) for the value to update

* Request Body::

        Host: example.com
        Accept: application/json
        Authorization: Bearer h480djs93hd8
        If-Match: "2"

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "displayName":"uaa.admins",
          "meta":{
            "attributes":["description"]
          },
          "members":[
             {"value":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f","operation":"delete"},
             {"type":"USER","authorities":["READ", "WRITE"],"value":"40c44bda-8b70-f771-74a2-3ebe4bda40c4","origin":"uaa"}
          ],
          "description": "A new description"
        }

* Response Body:
        As for create operation, returns the entire, updated record, with the Location header pointing to the resource.

* Response Codes::

        200 - Updated successfully
        400 - Bad Request
        401 - Unauthorized
        404 - Not found
        409 - Conflict

As with the create operation, members.value sub-attributes MUST refer to a valid SCIM resource id in the UAA, i.e the UUID of a an existing SCIM user or group.


Query for Information: ``GET /Groups``
--------------------------------------

See `SCIM - List/Query Resources`__

__ http://www.simplecloud.info/specs/draft-scim-api-01.html#query-resources

Get information about a group, including its members and what roles they hold within the group itself, i.e which members are group admins vs. which members are just members, and so on.

Filters: note that, per the specification, attribute values are comma separated and the filter expressions can be combined with boolean keywords ("or" and "and").

* Request: ``GET /Groups?attributes={requestedAttributes}&filter={filter}``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.read
        aud = scim

* Response Body (for ``GET /Groups?attributes=id&filter=displayName eq "uaa.admin"``)::

        HTTP/1.1 200 OK
        Content-Type: application/json

        {
          "totalResults":1,
          "schemas":["urn:scim:schemas:core:1.0"],
          "resources":[
            {
              "id":"123456"
            }
          ]
        }


* Response Codes::

        200 - Success
        400 - Bad Request
        401 - Unauthorized

Delete a Group: ``DELETE /Groups/{id}``
---------------------------------------

See `SCIM - Deleting Resources <http://www.simplecloud.info/specs/draft-scim-api-01.html#delete-resource>`_.

* Request: ``DELETE /Groups/{id}``
* Request Headers:

  + Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

  + ``If-Match`` the ``ETag`` (version id) for the value to delete

* Request Body: Empty
* Response Body: Empty
* Response Codes::

        200 - Success
        401 - Unauthorized
        404 - Not found

Deleting a group also removes the group from the 'groups' sub-attribute on users who were members of the group.


Create a Zone Manager (add a user to any of the `zone management groups`_): ``POST /Groups/zones``
--------------------------------------------------------------------------------------------------

See `SCIM - Creating Resources`__

__ http://www.simplecloud.info/specs/draft-scim-api-01.html#create-resource

.. _create_zone_administrator:

* Request: ``POST /Groups/zones``
* Request Headers: Authorization header containing an OAuth2_ bearer token with::

        scope = scim.zones
        aud = scim

* Request Body::

        {
            "schemas":["urn:scim:schemas:core:1.0"],
            "displayName":"zones.26d3c171-88ac-438a-ae53-e633b7b5c461.admin",
            "members":[
                {"origin":"uaa","type":"USER","value":"1323700f-a6e4-4d7a-9d0e-320c82db794a"}
            ],
        }

The ``displayName`` is unique in the UAA, but is allowed to change.  Each group also has a fixed primary key which is a UUID (stored in the ``id`` field of the core schema).
The following zone management scopes are supported:

- zones.{zone id}.admin
- zones.{zone id}.idps.read
- zones.{zone id}.clients.admin
- zones.{zone id}.clients.write
- zones.{zone id}.clients.read
- zones.{zone id}.scim.read
- zones.{zone id}.scim.write
- zones.{zone id}.scim.create


* Response Body::

        HTTP/1.1 201 Created
        Content-Type: application/json
        Location: https://example.com/v1/Groups/uid=123456
        ETag: "0"

        {
          "id": "2bfee27f-513f-436d-8cee-0ab08c21d2f3",
          "schemas": [
            "urn:scim:schemas:core:1.0"
          ],
          "displayName": "zones.MyZoneId.admin",
          "members": [
            {
              "origin": "uaa",
              "type": "USER",
              "value": "bf7c1859-0c8b-423f-9b94-0cbf14322431"
            }
          ],
          "meta": {
            "version": 0,
            "created": "2015-01-27T12:35:09.725Z",
            "lastModified": "2015-01-27T12:35:09.725Z"
          }
        }

* Response Codes::

        201 - Created successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized
        403 - Forbidden (authenticated but insufficient scopes)

The members.value sub-attributes MUST refer to a valid SCIM resource id in the UAA, i.e the UUID of an existing SCIM user or group.

Remove a zone administrator: ``DELETE /Groups/zones/{userId}/{zoneId}/{scope}``
-------------------------------------------------------------------------------

See `SCIM - Deleting Resources <http://www.simplecloud.info/specs/draft-scim-api-01.html#delete-resource>`_.

* Request: ``DELETE /Groups/zones/{userId}/{zoneId}/{scope}``
* Request Headers:

  + Authorization header containing an OAuth2_ bearer token with::

        scope = scim.zones (in the default UAA zone)
        aud = scim

  + ``If-Match`` the ``ETag`` (version id) for the value to delete

* Request Body: Empty
* Response Body: Empty
* Response Codes::

        200 - Success
        401 - Unauthorized
        403 - Forbidden
        404 - Not found

The scope path variable can be one of the following

- admin
- idps.read
- clients.admin
- clients.write
- clients.read

List External Group mapping: ``GET /Groups/External``
-----------------------------------------------------

Retrieves external group mappings in the form of a search result.
The API ``GET /Groups/External/list`` is deprecated

* Request: ``GET /Groups/External``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.read
        aud = scim

* Request(Query) Parameters::

        startIndex - the start index of the pagination, default value is 1
        count - the number of results to retrieve, default value is 100
        filter - scim search filter, possible field names are groupId, externalGroup and displayName

* Request Body::

    TBD

* Response Body ::

      HTTP/1.1 200 Ok
      Content-Type: application/json
      {"resources":
        [
            {"groupId":"79f37b92-21db-4a3e-a28c-ff93df476eca","displayName":"internal.write","externalGroup":"cn=operators,ou=scopes,dc=test,dc=com","origin":"ldap"},
            {"groupId":"e66c720f-6f4b-4fb5-8b0a-37818045b5b7","displayName":"internal.superuser","externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com","origin":"ldap"},
            {"groupId":"ef325dad-63eb-46e6-800b-796f254e13ee","displayName":"organizations.acme","externalGroup":"cn=test_org,ou=people,o=springsource,o=org","origin":"ldap"},
            {"groupId":"f149154e-c131-4e84-98cf-05aa94cc6b4e","displayName":"internal.everything","externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com","origin":"ldap"},
            {"groupId":"f2be2506-45e3-412e-9d85-6420d7e4afe4","displayName":"internal.read","externalGroup":"cn=developers,ou=scopes,dc=test,dc=com","origin":"ldap"}
        ],
        "startIndex":1,
        "itemsPerPage":100,
        "totalResults":5,
        "schemas":["urn:scim:schemas:core:1.0"]
      }


* Response Codes::

        200 - Results retrieved successfully
        401 - Unauthorized
        403 - Forbidden - valid token but not enough privileges or invalid method

Create a Group mapping: ``POST /Groups/External``
-------------------------------------------------

Creates a group mapping with an internal UAA groups (scope) and an external group, for example LDAP DN.

* Request: ``POST /Groups/External``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

* Request Body(using group name)::

        {
          "displayName":"uaa.admin",
          "externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com",
          "origin":"ldap"
        }

* Request Body(using group ID)::

        {
          "groupId":"f2be2506-45e3-412e-9d85-6420d7e4afe3",
          "externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com",
          "origin":"ldap"
        }

The ``displayName`` is unique in the UAA, but is allowed to change.  Each group also has a fixed primary key which is a UUID (stored in the ``id`` field of the core schema).
It is possible to substitute the ``displayName`` field with a ``groupId`` field containing the UUID.

* Response Body::

        HTTP/1.1 201 Created
        Content-Type: application/json
        Location: https://example.com/v1/Groups/uid=123456
        ETag: "0"

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "id":"123456",
          "meta":{
            "version":0,
            "created":"2011-08-01T21:32:44.882Z",
            "lastModified":"2011-08-01T21:32:44.882Z"
          },
          "displayName":"uaa.admin",
          "groupId":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f",
          "externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com",
          "origin":"ldap"
        }

* Response Codes::

        201 - Created successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized


Remove a Group mapping: ``DELETE /Groups/External/groupId/{groupId}/externalGroup/{externalGroup}/origin/{origin}``
-------------------------------------------------------------------------------------------------------------------

Removes the group mapping between an internal UAA groups (scope) and an external group, for example LDAP DN.
The API ``DELETE /Groups/External/id/{groupId}/{externalGroup}`` is deprecated

* Request: ``DELETE /Groups/External/groupId/3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f/externalGroup/cn=superusers,ou=scopes,dc=test,dc=com/origin/ldap``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

* Response Body::

        HTTP/1.1 200 Ok
        Content-Type: application/json
        Location: https://example.com/v1/Groups/uid=123456
        ETag: "0"

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "id":"123456",
          "meta":{
            "version":0,
            "created":"2011-08-01T21:32:44.882Z",
            "lastModified":"2011-08-01T21:32:44.882Z"
          },
          "displayName":"uaa.admin",
          "groupId":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f",
          "externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com"
        }

* Response Codes::

        200 - Deleted successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized


Remove a Group mapping: ``DELETE /Groups/External/displayName/{displayName}/externalGroup/{externalGroup}/origin/{origin}``
---------------------------------------------------------------------------------------------------------------------------

Removes the group mapping between an internal UAA groups (scope) and an external group, for example LDAP DN.
The API ``DELETE /Groups/External/{displayName}/{externalGroup}`` is deprecated

* Request: ``DELETE /Groups/External/displayName/internal.everything/externalGroup/cn=superusers,ou=scopes,dc=test,dc=com/origin/ldap``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

* Response Body::

        HTTP/1.1 200 Ok
        Content-Type: application/json
        Location: https://example.com/v1/Groups/uid=123456
        ETag: "0"

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "id":"123456",
          "meta":{
            "version":0,
            "created":"2011-08-01T21:32:44.882Z",
            "lastModified":"2011-08-01T21:32:44.882Z"
          },
          "displayName":"internal.everything",
          "groupId":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f",
          "externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com"
          "origin":"ldap"
        }

* Response Codes::

        200 - Deleted successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized

Access Token Administration APIs
================================

OAuth2 protected resources which deal with listing and revoking access tokens.  To revoke a token with ``DELETE`` clients need to provide a ``jti`` (token identifier, not the token value) which can be obtained from the token list via the corresponding ``GET``.  This is to prevent token values from being logged in the server (``DELETE`` does not have a body).

Get the Token Signing Key: ``GET /token_key``
---------------------------------------------

An endpoint which returns the JSON Web Token (JWT) key, used by the UAA to sign JWT access tokens, and to be used by authorized clients to verify that a token came from the UAA. The key is in JSON Web Key format. For complete information about JSON Web Keys, see RFC 7517 (https://tools.ietf.org/html/rfc7517).
In the case when the token key is symmetric, signer key and verifier key are the same, then this call is authenticated with client credentials using the HTTP Basic method.

JWT signing keys are specified via the identity zone configuration (see ``/identity-zones``). An identity zone token policy can be configured with multiple keys for purposes of key rotation. When adding a new key, set its ID as the ``activeKeyId`` to use it to sign all new tokens. ``/introspect`` will continue to verify tokens signed with the previous signing key for as long as it is present in the ``keys`` of the identity zone's token policy. Remove it to invalidate all those tokens.

JWT tokens issued by the UAA contain a ``kid`` field, indicating which key should be used for verification of the token. In the case that this is not the primary key, use ``GET /token_keys`` to retrieve all currently valid keys, and select the key that matches the token's ``kid``.

================  =======================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``GET /token_key``
Request body      *empty*
Response body     *example* ::

                    HTTP/1.1 200 OK
                    Content-Type: text/plain

                    {
                        "kid":"keyIdSymmetric",
                        "alg":"HMACSHA256",
                        "value":"FYSDKJHfgdUydsFJSHDFKAJHDSF"
                    }

                    HTTP/1.1 200 OK
                    Content-Type: text/plain
                    {
                        "kid":"keyIdRSA",
                        "alg":"RS256",
                        "value":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\nrn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\nfYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\nLCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\nkqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\njfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\nJwIDAQAB\n-----END PUBLIC KEY-----",
                        "kty":"RSA",
                        "use":"sig",
                        "n":"ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtN3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZeAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feVP9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tVkkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=",
                        "e":"AQAB"
                    }

================  =======================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

The algorithm ("alg") tells the caller how to use the value (it is the
result of algorithm method in the `Signer` implementation used in the
token endpoint).  In this case it is an HMAC (symmetric) key, but you
might also see an asymmetric RSA public key with algorithm
"RS256").

Get Token Signing Keys: ``GET /token_keys``
---------------------------------------------

An endpoint which returns the list of JWT keys. To support key rotation, this list specifies the IDs of all currently valid keys. JWT tokens issued by the UAA contain a ``kid`` field, indicating which key should be used for verification of the token.

================  =======================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================
Request           ``GET /token_keys``
Request body      *empty*
Response body     *example* ::


                    HTTP/1.1 200 OK
                    Content-Type: text/plain
                    [
                        {
                            "kid":"keyId1",
                            "alg":"RS256",
                            "value":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\nrn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\nfYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\nLCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\nkqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\njfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\nJwIDAQAB\n-----END PUBLIC KEY-----",
                            "kty":"RSA",
                            "use":"sig",
                            "n":"ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtN3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZeAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feVP9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tVkkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=",
                            "e":"AQAB"
                        },
                        {
                            "kid":"keyId2",
                            "alg":"RS256",
                            "value":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\nrn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\nfYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\nLCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\nkqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\njfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\nJwIDAQAB\n-----END PUBLIC KEY-----",
                            "kty":"RSA",
                            "use":"sig",
                            "n":"ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtN3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZeAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feVP9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tVkkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=",
                            "e":"AQAB"
                        }
                    ]

================  =======================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================




Client Registration Administration APIs
=======================================

List Clients: ``GET /oauth/clients``
------------------------------------

==============  ===========================================================================
Request         ``GET /oauth/clients``
Request body    client details
Response code    ``200 OK`` if successful with client details in JSON response
Response body   *example* ::

                  HTTP/1.1 200 OK
                  {"foo": {
                    "client_id" : "foo",
                    "name" : "Foo Client Name",
                    "scope" : ["uaa.none"],
                    "resource_ids" : ["none"],
                    "authorities" : ["cloud_controller.read","cloud_controller.write","scim.read"],
                    "authorized_grant_types" : ["client_credentials"],
                    "lastModified" : 1426260091149
                  },
                  "bar": {
                    "client_id" : "bar",
                    "name" : "Bar Client Name",
                    "scope" : ["cloud_controller.read","cloud_controller.write","openid"],
                    "resource_ids" : ["none"],
                    "authorities" : ["uaa.none"],
                    "authorized_grant_types" : ["authorization_code"],
                    "lastModified" : 1426260091145
                  }}

==============  ===========================================================================


Inspect Client: ``GET /oauth/clients/{client_id}``
--------------------------------------------------

=============== ===============================================================
Request         ``GET /oauth/clients/{client_id}``
Request body    client details
Response code    ``200 OK`` if successful with client details in JSON response
Response body   *example*::

                  HTTP/1.1 200 OK
                  {
                    "client_id" : "foo",
                    "name" : "Foo Client Name",
                    "scope" : ["uaa.none"],
                    "resource_ids" : ["none"],
                    "authorities" : ["cloud_controller.read","cloud_controller.write","scim.read"],
                    "authorized_grant_types" : ["client_credentials"],
                    "lastModified" : 1426260091145
                  }

=============== ===============================================================

Register Client: ``POST /oauth/clients``
----------------------------------------

==============  ===============================================
Request         ``POST /oauth/clients``
Request body    client details
Response code    ``201 CREATED`` if successful
Response body   the client details
==============  ===============================================

Example request::

    POST /oauth/clients
    {
      "client_id" : "foo",
      "name" : "Foo Client Name",
      "client_secret" : "fooclientsecret", // optional for untrusted clients
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200
      "redirect_uri":["http://test1.com","http*://ant.path.wildcard/**/passback/*"]
    }

(Also available for grant types that support it: ``refresh_token_validity``.)

Update Client: ``PUT /oauth/clients/{client_id}``
-------------------------------------------------

==============  ===============================================
Request         ``PUT /oauth/clients/{client_id}``
Request body    client details
Response code   ``200 OK`` if successful
Response body   the updated details
==============  ===============================================

Example::

    PUT /oauth/clients/foo
    {
      "client_id" : "foo",
      "name" : "New Foo Client Name",
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"]
      "redirect_uri":["http://test1.com","http*://ant.path.wildcard/**/passback/*"]
    }

N.B. the secret will not be changed, even if it is included in the
request body (use the secret change endpoint instead).

Delete Client: ``DELETE /oauth/clients/{client_id}``
----------------------------------------------------

==============  ===============================================
Request         ``DELETE /oauth/clients/{client_id}``
Request body    *empty*
Response code   ``200 OK``
Response body   the old client
==============  ===============================================



Change Client Secret: ``PUT /oauth/clients/{client_id}/secret``
---------------------------------------------------------------

==============  ===============================================
Request         ``PUT /oauth/clients/{client_id}/secret``
Request body    *secret change request*
Reponse code    ``200 OK`` if successful
Response body   a status message (hash)
==============  ===============================================

Example::

    PUT /oauth/clients/foo/secret
    {
      "oldSecret": "fooclientsecret",
      "secret": "newclientsceret"
    }


Change Client JWT Configuration: ``PUT /oauth/clients/{client_id}/clientjwt``
---------------------------------------------------------------

==============  ===============================================
Request         ``PUT /oauth/clients/{client_id}/clientjwt``
Request body    *jwt trust configuration change request*
Reponse code    ``200 OK`` if successful
Response body   a status message (hash)
==============  ===============================================

Example::

    PUT /oauth/clients/foo/clientjwt
    {
      "jwks_uri": "http://localhost:8080/uaa/token_keys"
    }


Register Multiple Clients: ``POST /oauth/clients/tx``
-----------------------------------------------------

==============  ===============================================
Request         ``POST /oauth/clients/tx``
Request body    an array of client details
Response code    ``201 CREATED`` if successful
Response body   an array of client details
Transactional   either all clients get registered or none
Scope Required  clients.admin
==============  ===============================================

Example request::

    POST /oauth/clients/tx
    [{
      "client_id" : "foo",
      "name" : "Foo Client Name",
      "client_secret" : "fooclientsecret", // optional for untrusted clients
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200
    },
    {
      "client_id" : "bar",
      "name" : "Bar Client Name",
      "client_secret" : "barclientsecret", // optional for untrusted clients
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200
    }]




Update Multiple Clients: ``PUT /oauth/clients/tx``
--------------------------------------------------

==============  ===============================================
Request         ``PUT /oauth/clients/tx``
Request body    an array of client details
Response code   ``200 OK`` if successful
Response body   an array of client details
Transactional   either all clients get updated or none
Scope Required  clients.admin
==============  ===============================================

Example::

    PUT /oauth/clients/tx
    [{
      "client_id" : "foo",
      "name" : "New Foo Client Name",
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"]
    },
    {
      "client_id" : "bar",
      "name" : "New Bar Client Name",
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"]
    }]

N.B. the secret will not be changed, even if it is included in the
request body (use the secret change endpoint instead).

Register, update or delete Multiple Clients: ``POST /oauth/clients/tx/modify``
------------------------------------------------------------------------------

==============  ===============================================
Request         ``POST /oauth/clients/tx/modify``
Request body    an array of client details
Response code    ``200 OK`` if successful
Response body   an array of client details
Transactional   either all clients get added/updated/deleted or no changes are performed
Scope Required  clients.admin
Rules           The 'secret' and 'update,secret' will change the secret and delete approvals.
                To change secret without deleting approvals use the /oauth/clients/tx/secret API
==============  ===============================================

Example request::

    POST /oauth/clients/tx/modify
    [{
      "client_id" : "foo",
      "name" : "Foo Client Name",
      "client_secret" : "fooclientsecret", // optional for untrusted clients
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200,
      "action" : "add"
    },
    {
      "client_id" : "bar",
      "name" : "New Bar Client Name",
      "client_secret" : "barclientsecret", // ignored and not required for an update
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200,
      "action" : "update"
    },
    {
      "client_id" : "bar",
      "client_secret" : "barclientsecret", //new secret - if changed, approvals are deleted
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200,
      "action" : "update,secret"
    },
    {
      "client_id" : "zzz",
      "action" : "delete"
    },
    {
      "client_id" : "zzz",
      "client_secret" : "zzzclientsecret", // new password, if changed client approvals are deleted
      "action" : "secret"
    }]

Change Multiple Client Secrets: ``POST /oauth/clients/tx/secret``
-----------------------------------------------------------------

==============  ===============================================
Request         ``POST /oauth/clients/tx/secret``
Request body    *an array of secret change request*
Reponse code    ``200 OK`` if successful
Response body   a list of all the clients that had their secret changed.
Transactional   either all clients' secret changed or none
Scope Required  clients.admin
Rules           The 'secret' and 'update,secret' will change the secret and delete approvals.
                To change secret without deleting approvals use the /oauth/clients/tx/secret API
==============  ===============================================

Example::

    POST /oauth/clients/tx/secret
    [{
      "clientId" : "foo",
      "oldSecret": "fooclientsecret",
      "secret": "newfooclientsceret"
    },{
      "clientId" : "bar",
      "oldSecret": "barclientsecret",
      "secret": "newbarclientsceret"
    }]


Delete Multiple Clients: ``POST /oauth/clients/tx/delete``
----------------------------------------------------------

==============  ===============================================
Request         ``POST /oauth/clients/tx/delete``
Request body    an array of clients to be deleted
Response code   ``200 OK``
Response body   an array of the deleted clients
Transactional   either all clients get deleted or none
==============  ===============================================

List Restricted Scopes: ``GET /oauth/clients/restricted``
---------------------------------------------------------

The UAA also supports creating and modifying clients that are considered 'restricted'.
The definition of a restricted client is a client that does not have any UAA admin scopes/
The operations to the the restricted endpoints follow the same syntax as creating, updating
clients using the regular APIs. If the client being created or updated contains
a restricted scopes or authorities, a 400 Bad Request is returned.

==============  ===========================================================================
Request         ``GET /oauth/clients/restricted``
Request body    none
Response code   ``200 OK`` if successful
Response body   List<String> - a list of scopes that are considered admin scopes in the UAA
==============  ===========================================================================

Creating Restricted Client: ``POST /oauth/clients/restricted``
--------------------------------------------------------------

==============  ===========================================================================
Request         ``POST /oauth/clients/restricted``
Request body    ClientDetails
Response code   ``201 CREATED`` if successful, 400 if validation of restricted scopes fails
Response body   ClientDetails - the newly created client
==============  ===========================================================================


Updating Restricted Client: ``PUT /oauth/clients/restricted/{client_id}``
-------------------------------------------------------------------------

==============  ===========================================================================
Request         ``PUT /oauth/clients/restricted/{client_id}``
Request body    ClientDetails
Response code   ``200 OK`` if successful, 400 if validation of restricted scopes fails
Response body   ClientDetails - the newly created client
==============  ===========================================================================

Client Metadata Administration APIs
===================================

Add or Modify Client Metadata: ``PUT /oauth/clients/{client_id}/meta``
----------------------------------------------------------------------

==============  ===========================================================================
Request         ``PUT /oauth/client/{client_id}/meta``
Request body    ClientMetadata (same as example payload in Response body)
Response code    ``200 OK`` if successful with client details in JSON response
Response body   *example* ::

                  HTTP/1.1 200 OK
                  {
                    "clientId" : "foo",
                    "showOnHomePage" : true,
                    "appLaunchUrl" : "http://foo.com/url",
                    "appIcon" : "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAXRQTFRFAAAAOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozk4Ojo6Ojk5NkZMFp/PFqDPNkVKOjo6Ojk5MFhnEq3nEqvjEqzjEbDpMFdlOjo5Ojo6Ojo6Ozg2GZ3TFqXeFKfgF6DVOjo6Ozg2G5jPGZ7ZGKHbGZvROjo6Ojo5M1FfG5vYGp3aM1BdOjo6Ojo6Ojk4KHWeH5PSHpTSKHSbOjk4Ojo6Ojs8IY/QIY/QOjs7Ojo6Ojo6Ozc0JYfJJYjKOzYyOjo5Ozc0KX7AKH/AOzUxOjo5Ojo6Ojo6Ojo6Ojs8LHi6LHi6Ojs7Ojo6Ojo6Ojo6Ojo6Ojo6L3K5L3S7LnW8LnS7Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6NlFvMmWeMmaeNVJwOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojk5Ojk4Ojk4Ojk5Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6FaXeFabfGZ/aGKDaHJnVG5rW////xZzURgAAAHV0Uk5TAAACPaXbAVzltTa4MykoM5HlPY/k5Iw85QnBs2D7+lzAtWD7+lyO6EKem0Ey47Mx2dYvtVZVop5Q2i4qlZAnBiGemh0EDXuddqypcHkShPJwYufmX2rvihSJ+qxlg4JiqP2HPtnW1NjZ2svRVAglGTi91RAXr3/WIQAAAAFiS0dEe0/StfwAAAAJcEhZcwAAAEgAAABIAEbJaz4AAADVSURBVBjTY2BgYGBkYmZhZWVhZmJkAANGNnYODk5ODg52NrAIIyMXBzcPLx8/NwcXIyNYQEBQSFhEVExcQgAiICklLSNbWiYnLy0lCRFQUFRSLq9QUVVUgAgwqqlraFZWaWmrqzFCTNXR1dM3MDQy1tWB2MvIaMJqamZuYWnCCHeIlbWNrZ0VG5QPFLF3cHRydoErcHVz9/D08nb3kYSY6evnHxAYFBwSGhYeAbbWNzIqOiY2Lj4hMckVoiQ5JTUtPSMzKzsH6pfcvPyCwqKc4pJcoAAA2pghnaBVZ0kAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTUtMTAtMDhUMTI6NDg6MDkrMDA6MDDsQS6eAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE1LTEwLTA4VDEyOjQ4OjA5KzAwOjAwnRyWIgAAAEZ0RVh0c29mdHdhcmUASW1hZ2VNYWdpY2sgNi43LjgtOSAyMDE0LTA1LTEyIFExNiBodHRwOi8vd3d3LmltYWdlbWFnaWNrLm9yZ9yG7QAAAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6aGVpZ2h0ADE5Mg8AcoUAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgAMTky06whCAAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNDQ0MzA4NDg5qdC9PQAAAA90RVh0VGh1bWI6OlNpemUAMEJClKI+7AAAAFZ0RVh0VGh1bWI6OlVSSQBmaWxlOi8vL21udGxvZy9mYXZpY29ucy8yMDE1LTEwLTA4LzJiMjljNmYwZWRhZWUzM2ViNmM1Mzg4ODMxMjg3OTg1Lmljby5wbmdoJKG+AAAAAElFTkSuQmCC" // base64 encoded image
                  }
Scope Required  ``clients.write`` or ``clients.admin``
==============  ===========================================================================


Get Client Metadata: ``GET /oauth/clients/{client_id}/meta``
------------------------------------------------------------

=============== ===============================================================
Request         ``GET /oauth/clients/{client_id}/meta``
Request body    none
Response code    ``200 OK`` if successful with client details in JSON response
Response body   *example*::

                  HTTP/1.1 200 OK
                  {
                    "clientId" : "foo",
                    "showOnHomePage" : true,
                    "appLaunchUrl" : "http://foo.com/url",
                    "appIcon" : "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAXRQTFRFAAAAOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozk4Ojo6Ojk5NkZMFp/PFqDPNkVKOjo6Ojk5MFhnEq3nEqvjEqzjEbDpMFdlOjo5Ojo6Ojo6Ozg2GZ3TFqXeFKfgF6DVOjo6Ozg2G5jPGZ7ZGKHbGZvROjo6Ojo5M1FfG5vYGp3aM1BdOjo6Ojo6Ojk4KHWeH5PSHpTSKHSbOjk4Ojo6Ojs8IY/QIY/QOjs7Ojo6Ojo6Ozc0JYfJJYjKOzYyOjo5Ozc0KX7AKH/AOzUxOjo5Ojo6Ojo6Ojo6Ojs8LHi6LHi6Ojs7Ojo6Ojo6Ojo6Ojo6Ojo6L3K5L3S7LnW8LnS7Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6NlFvMmWeMmaeNVJwOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojk5Ojk4Ojk4Ojk5Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6FaXeFabfGZ/aGKDaHJnVG5rW////xZzURgAAAHV0Uk5TAAACPaXbAVzltTa4MykoM5HlPY/k5Iw85QnBs2D7+lzAtWD7+lyO6EKem0Ey47Mx2dYvtVZVop5Q2i4qlZAnBiGemh0EDXuddqypcHkShPJwYufmX2rvihSJ+qxlg4JiqP2HPtnW1NjZ2svRVAglGTi91RAXr3/WIQAAAAFiS0dEe0/StfwAAAAJcEhZcwAAAEgAAABIAEbJaz4AAADVSURBVBjTY2BgYGBkYmZhZWVhZmJkAANGNnYODk5ODg52NrAIIyMXBzcPLx8/NwcXIyNYQEBQSFhEVExcQgAiICklLSNbWiYnLy0lCRFQUFRSLq9QUVVUgAgwqqlraFZWaWmrqzFCTNXR1dM3MDQy1tWB2MvIaMJqamZuYWnCCHeIlbWNrZ0VG5QPFLF3cHRydoErcHVz9/D08nb3kYSY6evnHxAYFBwSGhYeAbbWNzIqOiY2Lj4hMckVoiQ5JTUtPSMzKzsH6pfcvPyCwqKc4pJcoAAA2pghnaBVZ0kAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTUtMTAtMDhUMTI6NDg6MDkrMDA6MDDsQS6eAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE1LTEwLTA4VDEyOjQ4OjA5KzAwOjAwnRyWIgAAAEZ0RVh0c29mdHdhcmUASW1hZ2VNYWdpY2sgNi43LjgtOSAyMDE0LTA1LTEyIFExNiBodHRwOi8vd3d3LmltYWdlbWFnaWNrLm9yZ9yG7QAAAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6aGVpZ2h0ADE5Mg8AcoUAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgAMTky06whCAAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNDQ0MzA4NDg5qdC9PQAAAA90RVh0VGh1bWI6OlNpemUAMEJClKI+7AAAAFZ0RVh0VGh1bWI6OlVSSQBmaWxlOi8vL21udGxvZy9mYXZpY29ucy8yMDE1LTEwLTA4LzJiMjljNmYwZWRhZWUzM2ViNmM1Mzg4ODMxMjg3OTg1Lmljby5wbmdoJKG+AAAAAElFTkSuQmCC" // base64 encoded image
                  }
Scope Required  ``clients.read`` or ``clients.admin``
=============== ===============================================================

Get All Client Metadata: ``GET /oauth/clients/meta``
----------------------------------------------------

=============== ===============================================================
Request         ``GET /oauth/clients/meta``
Request body    none
Response code    ``200 OK`` if successful with client details in JSON response
Response body   *example*::

                  HTTP/1.1 200 OK
                  [{
                    "clientId" : "foo",
                    "showOnHomePage" : true,
                    "appLaunchUrl" : "http://foo.com/url",
                    "appIcon" : "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAXRQTFRFAAAAOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozk4Ojo6Ojk5NkZMFp/PFqDPNkVKOjo6Ojk5MFhnEq3nEqvjEqzjEbDpMFdlOjo5Ojo6Ojo6Ozg2GZ3TFqXeFKfgF6DVOjo6Ozg2G5jPGZ7ZGKHbGZvROjo6Ojo5M1FfG5vYGp3aM1BdOjo6Ojo6Ojk4KHWeH5PSHpTSKHSbOjk4Ojo6Ojs8IY/QIY/QOjs7Ojo6Ojo6Ozc0JYfJJYjKOzYyOjo5Ozc0KX7AKH/AOzUxOjo5Ojo6Ojo6Ojo6Ojs8LHi6LHi6Ojs7Ojo6Ojo6Ojo6Ojo6Ojo6L3K5L3S7LnW8LnS7Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6NlFvMmWeMmaeNVJwOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojk5Ojk4Ojk4Ojk5Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6FaXeFabfGZ/aGKDaHJnVG5rW////xZzURgAAAHV0Uk5TAAACPaXbAVzltTa4MykoM5HlPY/k5Iw85QnBs2D7+lzAtWD7+lyO6EKem0Ey47Mx2dYvtVZVop5Q2i4qlZAnBiGemh0EDXuddqypcHkShPJwYufmX2rvihSJ+qxlg4JiqP2HPtnW1NjZ2svRVAglGTi91RAXr3/WIQAAAAFiS0dEe0/StfwAAAAJcEhZcwAAAEgAAABIAEbJaz4AAADVSURBVBjTY2BgYGBkYmZhZWVhZmJkAANGNnYODk5ODg52NrAIIyMXBzcPLx8/NwcXIyNYQEBQSFhEVExcQgAiICklLSNbWiYnLy0lCRFQUFRSLq9QUVVUgAgwqqlraFZWaWmrqzFCTNXR1dM3MDQy1tWB2MvIaMJqamZuYWnCCHeIlbWNrZ0VG5QPFLF3cHRydoErcHVz9/D08nb3kYSY6evnHxAYFBwSGhYeAbbWNzIqOiY2Lj4hMckVoiQ5JTUtPSMzKzsH6pfcvPyCwqKc4pJcoAAA2pghnaBVZ0kAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTUtMTAtMDhUMTI6NDg6MDkrMDA6MDDsQS6eAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE1LTEwLTA4VDEyOjQ4OjA5KzAwOjAwnRyWIgAAAEZ0RVh0c29mdHdhcmUASW1hZ2VNYWdpY2sgNi43LjgtOSAyMDE0LTA1LTEyIFExNiBodHRwOi8vd3d3LmltYWdlbWFnaWNrLm9yZ9yG7QAAAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6aGVpZ2h0ADE5Mg8AcoUAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgAMTky06whCAAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNDQ0MzA4NDg5qdC9PQAAAA90RVh0VGh1bWI6OlNpemUAMEJClKI+7AAAAFZ0RVh0VGh1bWI6OlVSSQBmaWxlOi8vL21udGxvZy9mYXZpY29ucy8yMDE1LTEwLTA4LzJiMjljNmYwZWRhZWUzM2ViNmM1Mzg4ODMxMjg3OTg1Lmljby5wbmdoJKG+AAAAAElFTkSuQmCC" // base64 encoded image
                  },{
                    "clientId" : "bar",
                    "showOnHomePage" : true,
                    "appLaunchUrl" : "http://bar.com/url",
                    "appIcon" : "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAXRQTFRFAAAAOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ozk4Ojo6Ojk5NkZMFp/PFqDPNkVKOjo6Ojk5MFhnEq3nEqvjEqzjEbDpMFdlOjo5Ojo6Ojo6Ozg2GZ3TFqXeFKfgF6DVOjo6Ozg2G5jPGZ7ZGKHbGZvROjo6Ojo5M1FfG5vYGp3aM1BdOjo6Ojo6Ojk4KHWeH5PSHpTSKHSbOjk4Ojo6Ojs8IY/QIY/QOjs7Ojo6Ojo6Ozc0JYfJJYjKOzYyOjo5Ozc0KX7AKH/AOzUxOjo5Ojo6Ojo6Ojo6Ojs8LHi6LHi6Ojs7Ojo6Ojo6Ojo6Ojo6Ojo6L3K5L3S7LnW8LnS7Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6NlFvMmWeMmaeNVJwOjo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojk5Ojk4Ojk4Ojk5Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6FaXeFabfGZ/aGKDaHJnVG5rW////xZzURgAAAHV0Uk5TAAACPaXbAVzltTa4MykoM5HlPY/k5Iw85QnBs2D7+lzAtWD7+lyO6EKem0Ey47Mx2dYvtVZVop5Q2i4qlZAnBiGemh0EDXuddqypcHkShPJwYufmX2rvihSJ+qxlg4JiqP2HPtnW1NjZ2svRVAglGTi91RAXr3/WIQAAAAFiS0dEe0/StfwAAAAJcEhZcwAAAEgAAABIAEbJaz4AAADVSURBVBjTY2BgYGBkYmZhZWVhZmJkAANGNnYODk5ODg52NrAIIyMXBzcPLx8/NwcXIyNYQEBQSFhEVExcQgAiICklLSNbWiYnLy0lCRFQUFRSLq9QUVVUgAgwqqlraFZWaWmrqzFCTNXR1dM3MDQy1tWB2MvIaMJqamZuYWnCCHeIlbWNrZ0VG5QPFLF3cHRydoErcHVz9/D08nb3kYSY6evnHxAYFBwSGhYeAbbWNzIqOiY2Lj4hMckVoiQ5JTUtPSMzKzsH6pfcvPyCwqKc4pJcoAAA2pghnaBVZ0kAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTUtMTAtMDhUMTI6NDg6MDkrMDA6MDDsQS6eAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE1LTEwLTA4VDEyOjQ4OjA5KzAwOjAwnRyWIgAAAEZ0RVh0c29mdHdhcmUASW1hZ2VNYWdpY2sgNi43LjgtOSAyMDE0LTA1LTEyIFExNiBodHRwOi8vd3d3LmltYWdlbWFnaWNrLm9yZ9yG7QAAAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6aGVpZ2h0ADE5Mg8AcoUAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgAMTky06whCAAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNDQ0MzA4NDg5qdC9PQAAAA90RVh0VGh1bWI6OlNpemUAMEJClKI+7AAAAFZ0RVh0VGh1bWI6OlVSSQBmaWxlOi8vL21udGxvZy9mYXZpY29ucy8yMDE1LTEwLTA4LzJiMjljNmYwZWRhZWUzM2ViNmM1Mzg4ODMxMjg3OTg1Lmljby5wbmdoJKG+AAAAAElFTkSuQmCC" // base64 encoded image
                  }]
=============== ===============================================================

UI Endpoints
============

Web app clients need UI endpoints for the OAuth2 and OpenID
redirects. Clients that do not ask for a JSON content type will get
HTML.  Note that these UIs are whitelabeled and the branded versions
used in Cloud Foundry are deployed in a separate component (the Login Server).

Internal Login Form: ``GET /login``
-----------------------------------

* Request: ``GET /login?error={error}``
* Response Body: form with all the relevant prompts
* Response Codes: ``200 - Success``

Internal Login: ``POST /login.do``
----------------------------------

* Request: ``POST /login.do``
* Request Body, example -- depends on configuration (e.g. do we need OTP / PIN / password etc.)::

    username={username}&password={password}&X-Uaa-Csrf={token}...

* Response Header, includes location if redirect, and cookie for subsequent interaction (e.g. authorization)::

    Location: http://myapp.cloudfoundry.com/mycoolpage
    Set-Cookie: JSESSIONID=ldfjhsdhafgkasd
    Set-Cookie: X-Uaa-Csrf=abcdef; Expires=Thu, 04-Aug-2016 18:10:38 GMT; HttpOnly

* Response Codes::

    302 - Found
    200 - Success

Logout: ``GET /logout.do``
------------------------

The UAA can act as a Single Sign On server for the Cloud Foundry
platform (and possibly user apps as well), so if a user logs out they log out of all the apps.

OAuth2 Authorization Confirmation: ``GET /oauth/authorize/confirm_access``
--------------------------------------------------------------------------

* Request: ``GET /oauth/authorize/confirm_access``
* Request Body: HTML form posts back to ``/oauth/authorize``::

    Do you approve the application "foo" to access your CloudFoundry
    resources with scope "read_cloudfoundry"? Approve/Deny.

* Response Codes::

    200 - Success

OAuth2 Authorization: ``POST /oauth/authorize?user_oauth_approval=true``
------------------------------------------------------------------------

The precise form of this request is not given by the spec (which just says "obtain authorization"), but the response is.

* Request: ``POST /oauth/authorize?user_oauth_approval=true``
* Request Header (needed to ensure the currently authenticated client is the one that is authorizing)::

    Cookie: JSESSIONID=ldfjhsdhafgkasd

* Response Header: location as defined in the spec (e.g. includes auth code for that grant type, and error information)
* Response Codes::

    302 - Found

External Hosted Login Form (OpenID): ``GET /login``
---------------------------------------------------

==================  ===============================================
Request             ``GET /login``
Response Code       ``302 - Found``
Response Headers    ::

                     Location: http://www.google.com/etc/blah
                     Set-Cookie: JSESSIONID=ldfjhsdhafgkasd

==================  ===============================================

SAML Service Provider (SP) Metadata: ``GET /saml/metadata``
-----------------------------------------------------------

==================  ===============================================
Request             ``GET /saml/metadata``
Response Code       ``200 - Found``
Response Headers    ::

                     Content-Type: text/html;charset=utf-8

==================  ===============================================


Management Endpoints
====================
