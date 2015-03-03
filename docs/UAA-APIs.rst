==================================================
User Account and Authentication Service APIs
==================================================

.. contents:: Table of Contents

Overview
==============================================================

The User Account and Authentication Service (UAA):

* is a separate application from the Cloud Controller
* owns the user accounts and authentication sources
* is called via JSON APIs
* supports standard protocols to provide single sign-on and delegated authorization to web applications in addition to JSON APIs to support the Cloud Controller and team features of Cloud Foundry
* supports APIs and a basic login/approval UI for web client apps
* supports APIs for user account management for an external web UI (i.e. ``www.cloudfoundry.com``)

Rather than trigger arguments about how RESTful these APIs are we'll just refer to them as JSON APIs. Most of them are defined by the specs for the OAuth2_, `OpenID Connect`_, and SCIM_ standards.

.. _OAuth2: http://tools.ietf.org/html/draft-ietf-oauth-v2-26
.. _OpenID Connect: http://openid.net/openid-connect
.. _SCIM: http://simplecloud.info

Scopes authorized by the UAA
=======================
The UAA itself is also performing authorization based on the ``scope`` claim in the JWT token for it's operation.
Here is a summary of the different scopes that are known to the UAA.

  * oauth.approval - ``/approvals`` endpoint. Scope required to be able to approve/disapprove clients to act on a user's behalf. This is a default scope defined in uaa.yml.
  * approvals.me - not currently used
  * clients.secret - ``/oauth/clients/*/secret`` endpoint. Scope required to change the password of a client. Considered an admin scope.
  * oauth.login - Scope used to indicate a login application, such as the login-server, to perform trusted operations, such as create users not authenticated in the UAA.
  * openid - Required to access the /userinfo endpoint. Intended for OpenID clients.
  * scim.write - Admin write access to all SCIM endpoints, ``/Users``, ``/Groups/``.
  * scim.read - Admin read access to all SCIM endpoints, ``/Users``, ``/Groups/``.
  * scim.create - Reduced scope to be able to create a user using ``POST /Users`` (and verify their account using ``GET /Users/{id}/verify``) but not be able to modify, read or delete users.
  * scim.userids - ``/ids/Users`` - Required to convert a username+origin to a user ID and vice versa.
  * groups.update -
  * password.write - ``/User*/*/password`` endpoint. Admin scope to change a user's password.
  * uaa.user - scope to indicate this is a user
  * uaa.resource - scope to indicate this is a resource server
  * uaa.admin - scope to indicate this is the super user
  * uaa.none - scope to indicate that this client will not be performing actions on behalf of a user
  * clients.admin - super user scope to create, modify and delete clients
  * clients.write - scope required to create and modify clients. The scopes/authorities are limited to be prefixed with the scope holder's client id. For example, id:testclient authorities:client.write may create a client that has scopes/authorities that have the 'testclient.' prefix.
  * clients.read - scope to read information about clients
  * clients.secret - scope to change client secrets

A Note on Filtering
=======================
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
-------------------
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
=======================

Several modes of operation and other optional features can be set in configuration files.  Settings for a handful of standard scenarios can be externalized and switched using environment variables or system properties.

* Internal username/password authentication source

  The UAA manages a user account database. These accounts can be used for password based authentication similar to existing Cloud Foundry user accounts. The UAA accounts can be configured with password policy such as length, accepted/required character types, expiration times, reset policy, etc.

* Other Authentication sources

  Other standard external authentication sources can also be used. The most common and therefore the expected starting point are LDAP server, or an external OpenID provider (e.g. Google). Another expected authentication source would be Horizon Application Manager either through OAuth2 (preferred), or SAML protocols. General SAML2 support is not currently planned but could be added and would provide capabilities similar to OpenID and OAuth.

Authentication and Delegated Authorization APIs
===============================================================

This section deals with machine interactions, not with browsers, although some of them may have browsable content for authenticated users.  All machine requests have accept headers indicating JSON (or a derived media type perhaps).

The ``/userinfo``, ``/check_id``, and ``/token`` endpoints are specified in the `OpenID Connect`_ and `OAuth2`_ standards and should be used by web applications on a cloud foundry instance such as micro, www, support, but will not be used by flows from cf.

A Note on OAuth Scope
-----------------------

The OAuth2 spec includes a ``scope`` parameter as part of the token granting request which contains a set of scope values.  The spec leaves the business content of the scope up to the participants in the protocol - i.e. the scope values are completely arbitrary and can in principle be chosen by any Resource Server using the tokens.  Clients of the Resource Server have to ask for a valid scope to get a token, but the Authorization Server itself attaches no meaning to the scope - it just passes the value through to the Resource Server.  The UAA implementation of the Authorization Server has a couple of extra scope-related features (by virtue of being implemented in Spring Security where the features originate).

1. There is an optional step in client registration, where a client declares which scopes it will ask for, or alternatively where the Authorization Server can limit the scopes it can ask for. The Authorization Server can then check that token requests contain a valid scope (i.e. one of the set provided on registration).

2. The Resource Servers can each have a unique ID (e.g. a URI). And another optional part of a client registration is to provide a set of allowed resource ids for the client in question.  The Authorization Server binds the allowed resource ids to the token and then provides the information via the ``/check_token`` endpoint (in the ``aud`` claim), so that a Resource Server can check that its own ID is on the allowed list for the token before serving a resource.

Resource IDs have some of the character of a scope, except that the clients themselves don't need to know about them - it is information exchanged between the Authorization and Resource Servers.  The examples in this document use a ``scope`` parameter that indicates a resource server, e.g. a Cloud Controller instance. This is a suggested usage, but whether it is adopted by the real Cloud Controller is not crucial to the system.  Similarly any Resource Server that wants to can check the allowed resource IDs if there are any, but it is not mandatory to do so.

Authorization Code Grant
-------------------------

This is a completely vanilla as per the `OAuth2`_ spec, but we give a brief outline here for information purposes.

Browser Requests Code: ``GET /oauth/authorize``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

* Response Codes::

        302 - Found

*Sample uaac command for this flow*

* ``uaac -t token authcode get -c app -s appclientsecret``

*Sample curl commands for this flow*

* ``curl -v "http://localhost:8080/uaa/oauth/authorize?response_type=code&client_id=app&scope=password.write&redirect_uri=http%3A%2F%2Fwww.example.com%2Fcallback" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v http://localhost:8080/uaa/login.do -d "username=marissa&password=koala" --cookie cookies.txt --cookie-jar cookies.txt``
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
* ``curl -v -H "Accept:application/json" http://localhost:8080/uaa/login.do -d "username=marissa&password=koala" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v -H "Accept:application/json" "http://localhost:8080/uaa/oauth/authorize?response_type=code&client_id=app&scope=password.write&redirect_uri=http%3A%2F%2Fwww.example.com%2Fcallback" --cookie cookies.txt --cookie-jar cookies.txt``
* ``curl -v -H "Accept:application/json" http://localhost:8080/uaa/oauth/authorize -d "scope.0=scope.password.write&user_oauth_approval=true" --cookie cookies.txt --cookie-jar cookies.txt``

Client Obtains Token: ``POST /oauth/token``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

See `oauth2 token endpoint`_ below for a more detailed description.

=============== =================================================
Request         ``POST /oauth/token``
Request Body    the authorization code (form encoded), e.g.::

                  code=F45jH

Response Codes  ``200 OK``
Response Body   ::

                  {
                  "access_token":"2YotnFZFEjr1zCsicMWpAA",
                  "token_type":"bearer",
                  "expires_in":3600,
                  }

=============== =================================================

Implicit Grant with Credentials: ``POST /oauth/authorize``
------------------------------------------------------------

An `OAuth2`_ defined endpoint to provide various tokens and authorization codes.

For the ``cf`` flows, we use the OAuth2 Implicit grant type (to avoid a second round trip to ``/token`` and so cf does not need to securely store a client secret or user refresh tokens). The authentication method for the user is undefined by OAuth2 but a POST to this endpoint is acceptable, although a GET must also be supported (see `OAuth2 section 3.1`_).

.. _OAuth2 section 3.1: http://tools.ietf.org/html/draft-ietf-oauth-v2-26#section-3.1

Effectively this means that the endpoint is used to authenticate **and** obtain an access token in the same request.  Note the correspondence with the UI endpoints (this is similar to the ``/login`` endpoint with a different representation).

.. note:: A GET mothod is used in the `relevant section <http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-4.2.1>`_ of the spec that talks about the implicit grant, but a POST is explicitly allowed in the section on the ``/oauth/authorize`` endpoint (see `OAuth2 section 3.1`_).

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
-------------------------------------------------------

This works similarly to the previous section, but does not require the credentials to be POSTed as is needed for browser flows.

#. The browser redirects to the ``/oauth/authorize`` endpoint with parameters in the query component as per the previous section.
#. The UAA presents the UI to authenticate the user and approve the scopes.
#. If the user authorizes the scopes for the requesting client, the UAA will redirect the browser to the ``redirect_uri`` provided (and pre-registered) by the client.
#. Since the reply parameters are encoded in the location fragment, the client application must get the access token in the reply fragment from user's browser -- typically by returning a page to the browser with some javascript which will post the access token to the client app.

Trusted Authentication from Login Server
----------------------------------------

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint lets the login client to retrieve a user_id during an external authentication sequence.
So that the Authentication object in memory can always have a user_id available in the principal.
This endpoint is used

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Just a normal POST with approval parameters to ``/oauth/authorize``, including the cookie requested in Step 1 (just like a browser would do).  For example::

        POST /oauth/authorize
        Cookie: JSESSIONID=fkserygfkseyrgfv

        user_oauth_approval=true

Response::

        302 FOUND
        Location: https://app.cloudfoundry.com?code=jhkgh&state=kjhdafg


OAuth2 Token Validation Service: ``POST /check_token``
-------------------------------------------------------

An endpoint that allows a resource server such as the cloud controller to validate an access token. Interactions between the resource server and the authorization provider are not specified in OAuth2, so we are adding this endpoint. The request should be over SSL and use basic auth with the shared secret between the UAA and the resource server (which is stored as a client app registration). The POST body should be the access token and the response includes the userID, user_name and scope of the token in json format.  The client (not the user) is authenticated via basic auth for this call.

OAuth2 access tokens are opaque to clients, but can be decoded by resource servers to obtain all needed information such as userID, scope(s), lifetime, user attributes. If the token is encrypted witha shared sceret between the UAA are resource server it can be decoded without contacting the UAA. However, it may be useful -- at least during development -- for the UAA to specify a short, opaque token and then provide a way for the resource server to return it to the UAA to validate and open. That is what this endpoint does. It does not return general user account information like the /userinfo endpoint, it is specifically to validate and return the information represented by access token that the user presented to the resource server.

This endpoint mirrors the OpenID Connect ``/check_id`` endpoint, so not very RESTful, but we want to make it look and feel like the others. The endpoint is not part of any spec, but it is a useful tool to have for anyone implementing an OAuth2 Resource Server.

* Request: uses basic authorization with ``base64(resource_server:shared_secret)`` assuming the caller (a resource server) is actually also a registered client::

        POST /check_token HTTP/1.1
        Host: server.example.com
        Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        Content-Type: application/x-www-form-encoded

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

Notes:

* The ``user_name`` is the same as you get from the `OpenID Connect`_ ``/userinfo`` endpoint.  The ``user_id`` field is the same as you would use to get the full user profile from ``/Users``.
* Many of the fields in the response are a courtesy, allowing the caller to avoid further round trip queries to pick up the same information (e.g. via the ``/Users`` endpoint).
* The ``aud`` claim is the resource ids that are the audience for the token.  A Resource Server should check that it is on this list or else reject the token.
* The ``client_id`` data represent the client that the token was granted for, not the caller.  The value can be used by the caller, for example, to verify that the client has been granted permission to access a resource.
* Error Responses: see `OAuth2 Error responses <http://tools.ietf.org/html/draft-ietf-oauth-v2-26#section-5.2>`_ and this addition::

            HTTP/1.1 400 Bad Request
            Content-Type: application/json;charset=UTF-8
            Cache-Control: no-store
            Pragma: no-cache

            { "error":"invalid_token" }

.. _oauth2 token endpoint:

OAuth2 Token Endpoint: ``POST /oauth/token``
----------------------------------------------

An OAuth2 defined endpoint which accepts authorization code or refresh tokens and provides access_tokens. The access_tokens can then be used to gain access to resources within a resource server.

* Request: ``POST /oauth/token``

=============== =================================================
Request         ``POST /oauth/token``
Request Body    the authorization code (form encoded), e.g.::

                  code=F45jH

Response Codes  ``200 OK``
Response Body   ::

                  {
                  "access_token":"2YotnFZFEjr1zCsicMWpAA",
                  "token_type":"bearer",
                  "expires_in":3600,
                  }

=============== =================================================


Support for additional authorization attributes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Additional user defined claims can be added to the token by sending them in the token request. The format of the request is as follows::

        authorities={"additionalAuthorizationAttributes":{"external_group":"domain\\group1","external_id":"abcd1234"}}

A sample password grant request is as follows::

        POST /uaa/oauth/token HTTP/1.1
        Host: localhost:8080
        Accept: application/json
        Authorization: Basic YXBwOmFwcGNsaWVudHNlY3JldA==
        "grant_type=password&username=marissa&password=koala&authorities=%7B%22additionalAuthorizationAttributes%22%3A%7B%22external_group%22%3A%22domain%5C%5Cgroup1%22%2C%20%22external_id%22%3A%22abcd1234%22%7D%7D%0A"

The access token will contain an az_attr claim like::
        
        "az_attr":{"external_group":"domain\\group1","external_id":"abcd1234"}}

These attributes can be requested in an authorization code flow as well.

OpenID Check ID Endpoint: ``POST /check_id``
---------------------------------------------

An OpenID Connect defined endpoint. It accepts an id_token, which contains claims about the authentication event. It validates the token and returns information contained in the token in JSON format. Basically makes it so that clients do not need to have full token handling implementations.

==============  ======================================
Request         ``POST /check_id``
Request Body    ``id_token=LKFJHDSG567TDFHG``
==============  ======================================

OpenID User Info Endpoint: ``GET /userinfo``
----------------------------------------------

An OAuth2 protected resource and an OpenID Connect endpoint. Given an appropriate access\_token, returns information about a user. Defined fields include various standard user profile fields. The response may include other user information such as group membership.

=========== ===============================================
Request     ``GET /userinfo``
Response    ``{"user_id":"olds","email":"olds@vmare.com"}``
=========== ===============================================

.. _login information api:

Login Information API: ``GET /login``
---------------------------------------

An endpoint which returns login information, e.g prompts for authorization codes or one-time passwords. This allows cf to determine what login information it should collect from the user.

This call will be unauthenticated.

================  ===============================================
Request           ``GET /login_info`` or ``GET /login``
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

User Account Management APIs
================================

UAA supports the `SCIM <http://simplecloud.info>`_ standard for
these APIs and endpoints.  These endpoints are themselves secured by OAuth2, and access decision is done based on the 'scope' and 'aud' fields of the JWT OAuth2 token.

Create a User: ``POST /Users``
------------------------------

See `SCIM - Creating Resources`__

__ http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#create-resource

* Request: ``POST /Users``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

* Request Body::

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "userName":"bjensen",
          "name":{
            "formatted":"Ms. Barbara J Jensen III",
            "familyName":"Jensen",
            "givenName":"Barbara"
          }
        }

The ``userName`` is unique in the UAA, but is allowed to change.  Each user also has a fixed primary key which is a UUID (stored in the ``id`` field of the core schema).

* Response Body::

        HTTP/1.1 201 Created
        Content-Type: application/json
        Location: https://example.com/v1/User/uid=123456
        ETag: "0"

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "id":"123456",
          "externalId":"bjensen",
          "meta":{
            "version":0,
            "created":"2011-08-01T21:32:44.882Z",
            "lastModified":"2011-08-01T21:32:44.882Z"
          },
          "name":{
            "formatted":"Ms. Barbara J Jensen III",
            "familyName":"Jensen",
            "givenName":"Barbara"
          },
          "userName":"bjensen"
        }

* Response Codes::

        201 - Created successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized


Update a User: ``PUT /Users/{id}``
----------------------------------------

See `SCIM - Modifying with PUT <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#edit-resource-with-put>`_

* Request: ``PUT /Users/{id}``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

* Request Body::

        Host: example.com
        Accept: application/json
        Authorization: Bearer h480djs93hd8
        If-Match: "2"

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "id":"123456",
          "userName":"bjensen",
          "externalId":"bjensen",
          "name":{
            "formatted":"Ms. Barbara J Jensen III",
            "familyName":"Jensen",
            "givenName":"Barbara",
            "middleName":"Jane"

          },
          "emails":[
            {
                "value":"bjensen@example.com"
            },
            {
                "value":"babs@jensen.org"
            }
          ],
          "meta":{
            "version":2,
            "created":"2011-11-30T21:11:30.000Z",
            "lastModified":"2011-12-30T21:11:30.000Z"
          }
        }

* Response Body:
        As for create operation, returns the entire, updated record, with the Location header pointing to the resource.

* Response Codes::

        200 - Updated successfully
        400 - Bad Request
        401 - Unauthorized
        404 - Not found

  Note: SCIM also optionally supports partial update using PATCH.

Change Password: ``PUT /Users/{id}/password``
----------------------------------------------

See `SCIM - Changing Password <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#change-password>`_

* Request: ``PUT /Users/{id}/password``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = password.write
        aud = password

  OR ::

        user_id = {id} i.e id of the user whose password is being updated

* Request Body::

        Host: example.com
        Accept: application/json
        Authorization: Bearer h480djs93hd8

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "password": "newpassword",
          "oldPassword": "oldpassword"
        }

* Response Body: the updated details

* Response Codes::

        200 - Updated successfully
        400 - Bad Request
        401 - Unauthorized
        404 - Not found

.. note:: SCIM specifies that a password change is a PATCH, but since this isn't supported by many clients, we have used PUT.  SCIM offers the option to use POST with a header override - if clients want to send `X-HTTP-Method-Override` they can ask us to add support for that.

Verify User: ``GET /Users/{id}/verify``
----------------------------------------------


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

.. note:: SCIM specifies that a password change is a PATCH, but since this isn't supported by many clients, we have used PUT.  SCIM offers the option to use POST with a header override - if clients want to send `X-HTTP-Method-Override` they can ask us to add support for that.

Query for Information: ``GET /Users``
---------------------------------------

See `SCIM - List/Query Resources`__

__ http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#query-resources

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

See `SCIM - Deleting Resources <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#delete-resource>`_.

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
* Response Body: list of users matching the filter
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


Query the strength of a password: ``POST /password/score``
-----------------------------------------------------------

The password strength API is not part of SCIM but is provided as a service to allow user management applications to use the same password quality
checking mechanism as the UAA itself. Rather than specifying a set of rules based on the included character types (upper and lower case, digits, symbols etc), the UAA
exposes this API which accepts a candidate password and returns a JSON message containing a simple numeric score (between 0 and 10) and a required score
(one which is acceptable to the UAA). The score is based on a calculation using the ideas from the  `zxcvbn project`_.

.. _zxcvbn project: http://tech.dropbox.com/?p=165

The use of this API does not guarantee that a password is strong (it is currently limited to English dictionary searches, for example), but it will protect against some of
the worst choices that people make and will not unnecessarily penalise strong passwords. In addition to the password parameter itself, the client can pass a
comma-separated list of user-specific data in the ``userData`` parameter. This can be used to pass things like the username, email or other biographical
information known to the client which should result in a low score if it is used as part of the password.

* Request: ``POST /password/score``

    POST /password/score HTTP/1.1
    Host: uaa.example.com
    Content-Type: application/x-www-form-encoded

    password=password1&userData=jane,janesdogsname,janescity

* Response
    HTTP/1.1 200 OK
    Content-Type: application/json

    {"score": 0, "requiredScore": 5}


Group Management APIs
=========================
In addition to SCIM users, UAA also supports/implements SCIM_groups_ for managing group-membership of users. These endpoints too are secured by OAuth2 bearer tokens.

.. _SCIM_groups: http://tools.ietf.org/html/draft-ietf-scim-core-schema-00#section-8

Create a Group: ``POST /Groups``
----------------------------------

See `SCIM - Creating Resources`__

__ http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#create-resource

* Request: ``POST /Groups``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

* Request Body::

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "displayName":"uaa.admin",
          "members":[
	      { "type":"USER","authorities":["READ"],"value":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f" }
	  ]
        }

The ``displayName`` is unique in the UAA, but is allowed to change.  Each group also has a fixed primary key which is a UUID (stored in the ``id`` field of the core schema).

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
	      { "type":"USER","authorities":["READ"],"value":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f" }
          ]
        }

* Response Codes::

        201 - Created successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized

The members.value sub-attributes MUST refer to a valid SCIM resource id in the UAA, i.e the UUID of an existing SCIM user or group.

Update a Group: ``PUT /Groups/{id}``
----------------------------------------

See `SCIM - Modifying with PUT <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#edit-resource-with-put>`_

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
             {"type":"USER","authorities":["READ"],"value":"3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f"},
             {"type":"USER","authorities":["READ", "WRITE"],"value":"40c44bda-8b70-f771-74a2-3ebe4bda40c4"}
          ]	     
        }

* Response Body:
        As for create operation, returns the entire, updated record, with the Location header pointing to the resource.

* Response Codes::

        200 - Updated successfully
        400 - Bad Request
        401 - Unauthorized
        404 - Not found

As with the create operation, members.value sub-attributes MUST refer to a valid SCIM resource id in the UAA, i.e the UUID of a an existing SCIM user or group.

Note: SCIM also optionally supports partial update using PATCH, but UAA does not currently implement it.


Query for Information: ``GET /Groups``
---------------------------------------

See `SCIM - List/Query Resources`__

__ http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#query-resources

Get information about a group, including its members and what roles they hold within the group itself, i.e which members are group admins vs. which members are just members, and so on.

Filters: note that, per the specification, attribute values are comma separated and the filter expressions can be combined with boolean keywords ("or" and "and").

* Request: ``GET /Groups?attributes={requestedAttributes}&filter={filter}``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.read
        aud = scim

* Response Body (for ``GET /Groups?attributes=id&filter=displayName eq uaa.admin``)::

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
-----------------------------------------

See `SCIM - Deleting Resources <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#delete-resource>`_.

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


List External Group mapping: ``GET /Groups/External``
----------------------------------

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

* Response Body::

        HTTP/1.1 200 Ok
        Content-Type: application/json

        {"resources":
          [
            {"groupId":"79f37b92-21db-4a3e-a28c-ff93df476eca","displayName":"internal.write","externalGroup":"cn=operators,ou=scopes,dc=test,dc=com"},
            {"groupId":"e66c720f-6f4b-4fb5-8b0a-37818045b5b7","displayName":"internal.superuser","externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com"},
            {"groupId":"ef325dad-63eb-46e6-800b-796f254e13ee","displayName":"organizations.acme","externalGroup":"cn=test_org,ou=people,o=springsource,o=org"},
            {"groupId":"f149154e-c131-4e84-98cf-05aa94cc6b4e","displayName":"internal.everything","externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com"},
            {"groupId":"f2be2506-45e3-412e-9d85-6420d7e4afe4","displayName":"internal.read","externalGroup":"cn=developers,ou=scopes,dc=test,dc=com"}
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
----------------------------------

Creates a group mapping with an internal UAA groups (scope) and an external group, for example LDAP DN.

* Request: ``POST /Groups/External``
* Request Headers: Authorization header containing an `OAuth2`_ bearer token with::

        scope = scim.write
        aud = scim

* Request Body(using group name)::

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "displayName":"uaa.admin",
          "externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com"
        }

* Request Body(using group ID)::

        {
          "schemas":["urn:scim:schemas:core:1.0"],
          "groupId":"f2be2506-45e3-412e-9d85-6420d7e4afe3",
          "externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com"
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
          "externalGroup":"cn=superusers,ou=scopes,dc=test,dc=com"
        }

* Response Codes::

        201 - Created successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized

Remove a Group mapping: ``DELETE /Groups/External/groupId/{groupId}/externalGroup/{externalGroup}``
----------------------------------

Removes the group mapping between an internal UAA groups (scope) and an external group, for example LDAP DN.
The API ``DELETE /Groups/External/id/{groupId}/{externalGroup}`` is deprecated

* Request: ``DELETE /Groups/External/groupId/3ebe4bda-74a2-40c4-8b70-f771d9bc8b9f/externalGroup/cn=superusers,ou=scopes,dc=test,dc=com``
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

Remove a Group mapping: ``DELETE /Groups/External/displayName/{displayName}/externalGroup/{externalGroup}``
----------------------------------

Removes the group mapping between an internal UAA groups (scope) and an external group, for example LDAP DN.
The API ``DELETE /Groups/External/{displayName}/{externalGroup}`` is deprecated

* Request: ``DELETE /Groups/External/displayName/internal.everything/externalGroup/cn=superusers,ou=scopes,dc=test,dc=com``
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
        }

* Response Codes::

        200 - Deleted successfully
        400 - Bad Request (unparseable, syntactically incorrect etc)
        401 - Unauthorized

Access Token Administration APIs
=================================

OAuth2 protected resources which deal with listing and revoking access tokens.  To revoke a token with ``DELETE`` clients need to provide a ``jti`` (token identifier, not the token value) which can be obtained from the token list via the corresponding ``GET``.  This is to prevent token values from being logged in the server (``DELETE`` does not have a body).

Get the Token Signing Key: ``GET /token_key``
-----------------------------------------------

An endpoint which returns the JWT token key, used by the UAA to sign JWT access tokens, and to be used by authorized clients to verify that a token came from the UAA.
Key is in JSON Web Key format, for RSA public keys, the values n, modulues, and e, exponent, are available.
This call is authenticated with client credentials using the HTTP Basic method.

================  ==========================================
Request           ``GET /token_key``
Request body      *empty*
Response body     *example* ::

                    HTTP/1.1 200 OK
                    Content-Type: text/plain

                    {
                        "alg":"HMACSHA256",
                        "value":"FYSDKJHfgdUydsFJSHDFKAJHDSF"
                    }

                    HTTP/1.1 200 OK
                    Content-Type: text/plain
                    {
                        "alg":"SHA256withRSA",
                        "value":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\nrn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\nfYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\nLCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\nkqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\njfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\nJwIDAQAB\n-----END PUBLIC KEY-----",
                        "kty":"RSA",
                        "use":"sig",
                        "n":"ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtN3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZeAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feVP9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tVkkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=",
                        "e":"AQAB"
                    }
================  ==========================================

The algorithm ("alg") tells the caller how to use the value (it is the
result of algorithm method in the `Signer` implementation used in the
token endpoint).  In this case it is an HMAC (symmetric) key, but you
might also see an asymmetric RSA public key with algorithm
"SHA256withRSA").


Client Registration Administration APIs
========================================

List Clients: ``GET /oauth/clients``
-----------------------------------------------------

==============  ===========================================================================
Request         ``GET /oauth/clients``
Request body    client details
Response code    ``200 OK`` if successful with client details in JSON response
Response body   *example* ::

                  HTTP/1.1 200 OK
                  {"foo": {
                    "client_id" : "foo",
                    "scope" : ["uaa.none"],
                    "resource_ids" : ["none"],
                    "authorities" : ["cloud_controller.read","cloud_controller.write","scim.read"],
                    "authorized_grant_types" : ["client_credentials"]
                  },
                  "bar": {
                    "client_id" : "bar",
                    "scope" : ["cloud_controller.read","cloud_controller.write","openid"],
                    "resource_ids" : ["none"],
                    "authorities" : ["uaa.none"],
                    "authorized_grant_types" : ["authorization_code"]
                  }}

==============  ===========================================================================


Inspect Client: ``GET /oauth/clients/{client_id}``
-----------------------------------------------------

=============== ===============================================================
Request         ``GET /oauth/clients/{client_id}``
Request body    client details
Response code    ``200 OK`` if successful with client details in JSON response
Response body   *example*::

                  HTTP/1.1 200 OK
                  {
                    "client_id" : "foo",
                    "scope" : ["uaa.none"],
                    "resource_ids" : ["none"],
                    "authorities" : ["cloud_controller.read","cloud_controller.write","scim.read"],
                    "authorized_grant_types" : ["client_credentials"]
                  }

=============== ===============================================================

Register Client: ``POST /oauth/clients/{client_id}``
-------------------------------------------------------

==============  ===============================================
Request         ``POST /oauth/clients/{client_id}``
Request body    client details
Response code    ``201 CREATED`` if successful
Response body   the client details
==============  ===============================================

Example request::

    POST /oauth/clients/foo
    {
      "client_id" : "foo",
      "client_secret" : "fooclientsecret", // optional for untrusted clients
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200
    }

(Also available for grant types that support it: ``refresh_token_validity``.)

Update Client: ``PUT /oauth/clients/{client_id}``
------------------------------------------------------

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
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"]
    }

N.B. the secret will not be changed, even if it is included in the
request body (use the secret change endpoint instead).

Delete Client: ``DELETE /oauth/clients/{client_id}``
-------------------------------------------------------

==============  ===============================================
Request         ``DELETE /oauth/clients/{client_id}``
Request body    *empty*
Response code   ``200 OK``
Response body   the old client
==============  ===============================================



Change Client Secret: ``PUT /oauth/clients/{client_id}/secret``
------------------------------------------------------------------

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


Register Multiple Clients: ``POST /oauth/clients/tx``
-------------------------------------------------------

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
      "client_secret" : "fooclientsecret", // optional for untrusted clients
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200
    },
    {
      "client_id" : "bar",
      "client_secret" : "barclientsecret", // optional for untrusted clients
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"],
      "access_token_validity": 43200
    }]




Update Multiple Clients: ``PUT /oauth/clients/tx``
------------------------------------------------------

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
      "scope" : ["uaa.none"],
      "resource_ids" : ["none"],
      "authorities" : ["cloud_controller.read","cloud_controller.write","openid"],
      "authorized_grant_types" : ["client_credentials"]
    },
    {
      "client_id" : "foo",
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

    POST /oauth/clients/tx
    [{
      "client_id" : "foo",
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
------------------------------------------------------------------

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


UI Endpoints
==============

Web app clients need UI endpoints for the OAuth2 and OpenID
redirects. Clients that do not ask for a JSON content type will get
HTML.  Note that these UIs are whitelabeled and the branded versions
used in Cloud Foundry are deployed in a separate component (the Login Server).

Internal Login Form: ``GET /login``
-------------------------------------

* Request: ``GET /login?error={error}``
* Response Body: form with all the relevant prompts
* Response Codes: ``200 - Success``

Internal Login: ``POST /login.do``
-----------------------------------

* Request: ``POST /login.do``
* Request Body, example -- depends on configuration (e.g. do we need OTP / PIN / password etc.)::

    username={username}&password={password}...

* Response Header, includes location if redirect, and cookie for subsequent interaction (e.g. authorization)::

    Location: http://myapp.cloudfoundry.com/mycoolpage
    Set-Cookie: JSESSIONID=ldfjhsdhafgkasd

* Response Codes::

    302 - Found
    200 - Success

Logout: `GET /logout.do`
--------------------------------

The UAA can act as a Single Sign On server for the Cloud Foundry
platform (and possibly user apps as well), so if a user logs out he
logs out of all the apps.

OAuth2 Authorization Confirmation: ``GET /oauth/authorize/confirm_access``
---------------------------------------------------------------------------

* Request: ``GET /oauth/authorize/confirm_access``
* Request Body: HTML form posts back to ``/oauth/authorize``::

    Do you approve the application "foo" to access your CloudFoundry
    resources with scope "read_cloudfoundry"? Approve/Deny.

* Response Codes::

    200 - Success

OAuth2 Authorization: ``POST /oauth/authorize?user_oauth_approval=true``
-----------------------------------------------------------------------------

The precise form of this request is not given by the spec (which just says "obtain authorization"), but the response is.

* Request: ``POST /oauth/authorize?user_oauth_approval=true``
* Request Header (needed to ensure the currently authenticated client is the one that is authorizing)::

    Cookie: JSESSIONID=ldfjhsdhafgkasd

* Response Header: location as defined in the spec (e.g. includes auth code for that grant type, and error information)
* Response Codes::

    302 - Found

External Hosted Login Form (OpenID): ``GET /login``
----------------------------------------------------

==================  ===============================================
Request             ``GET /login``
Response Code       ``302 - Found``
Response Headers    ::

                     Location: http://www.google.com/etc/blah
                     Set-Cookie: JSESSIONID=ldfjhsdhafgkasd

==================  ===============================================


Management Endpoints
=====================

Basic Metrics: ``GET /varz``
---------------------------------

Authentication is via HTTP basic using credentials that are configured
via ``varz.username`` and ``varz.password``.  The ``/varz`` endpoint pulls
data out of the JMX ``MBeanServer``, exposing selected nuggets directly
for ease of use, and providing links to more detailed metrics.

* Request: ``GET /varz``
* Response Body::

    {
      "type": "UAA",
      "links": {
        "Users": "http://localhost:8080/uaa/varz/Users",
        "JMImplementation": "http://localhost:8080/uaa/varz/JMImplementation",
        "spring.application": "http://localhost:8080/uaa/varz/spring.application",
        "com.sun.management": "http://localhost:8080/uaa/varz/com.sun.management",
        "Catalina": "http://localhost:8080/uaa/varz/Catalina",
        "env": "http://localhost:8080/uaa/varz/env",
        "java.lang": "http://localhost:8080/uaa/varz/java.lang",
        "java.util.logging": "http://localhost:8080/uaa/varz/java.util.logging"
      },
      "mem": 19173496,
      "memory": {
        "verbose": false,
        "non_heap_memory_usage": {
          "max": 184549376,
          "committed": 30834688,
          "init": 19136512,
          "used": 30577744
        },
        "object_pending_finalization_count": 0,
        "heap_memory_usage": {
          "max": 902299648,
          "committed": 84475904,
          "init": 63338496,
          "used": 19173496
        }
      },
      "token_store": {
        "refresh_token_count": 0,
        "access_token_count": 0,
        "flush_interval": 1000
      },
      "audit_service": {
        "user_authentication_count": 0,
        "user_not_found_count": 0,
        "principal_authentication_failure_count": 1,
        "principal_not_found_count": 0,
        "user_authentication_failure_count": 0
      },
      "spring.profiles.active": []
    }

Detailed Metrics: ``GET /varz/{domain}``
-----------------------------------------

More detailed metrics can be obtained from the links in ``/varz``.  All
except the ``env`` link (the OS env vars) are just the top-level domains
in the JMX ``MBeanServer``.  In the case of ``Catalina`` there are some
known cycles in the object graph which we avoid by restricting the
result to the most interesting areas to do with request processing.

* Request: ``GET /varz/{domain}``
* Response Body (for domain=Catalina)::

    {
      "global_request_processor": {
        "http-8080": {
          "processing_time": 0,
          "max_time": 0,
          "request_count": 0,
          "bytes_sent": 0,
          "bytes_received": 0,
          "error_count": 0,
          "modeler_type": "org.apache.coyote.RequestGroupInfo"
        }
      }
    }

Beans from the Spring application context are exposed at
``/varz/spring.application``.
