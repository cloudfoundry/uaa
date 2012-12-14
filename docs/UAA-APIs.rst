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

.. _OAuth2: http://tools.ietf.org/id/draft-ietf-oauth-v2-26.html
.. _OpenID Connect: http://openid.net/openid-connect
.. _SCIM: http://simplecloud.info

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

The ``/userinfo``, ``/check_id``, and ``/token`` endpoints are specified in the `OpenID Connect`_ and OAuth2_ standards and should be used by web applications on a cloud foundry instance such as micro, www, support, but will not be used by flows from vmc.

A Note on OAuth Scope
-----------------------

The OAuth2 spec includes a ``scope`` parameter as part of the token granting request which contains a set of scope values.  The spec leaves the business content of the scope up to the participants in the protocol - i.e. the scope values are completely arbitrary and can in principle be chosen by any Resource Server using the tokens.  Clients of the Resource Server have to ask for a valid scope to get a token, but the Authorization Server itself attaches no meaning to the scope - it just passes the value through to the Resource Server.  The UAA implementation of the Authorization Server has a couple of extra scope-related features (by virtue of being implemented in Spring Security where the features originate).

1. There is an optional step in client registration, where a client declares which scopes it will ask for, or alternatively where the Authorization Server can limit the scopes it can ask for. The Authorization Server can then check that token requests contain a valid scope (i.e. one of the set provided on registration).

2. The Resource Servers can each have a unique ID (e.g. a URI). And another optional part of a client registration is to provide a set of allowed resource ids for the client in question.  The Authorization Server binds the allowed resource ids to the token and then provides the information via the ``/check_token`` endpoint (in the ``aud`` claim), so that a Resource Server can check that its own ID is on the allowed list for the token before serving a resource.

Resource IDs have some of the character of a scope, except that the clients themselves don't need to know about them - it is information exchanged between the Authorization and Resource Servers.  The examples in this document use a ``scope`` parameter that indicates a resource server, e.g. a Cloud Controller instance. This is a suggested usage, but whether it is adopted by the real Cloud Controller is not crucial to the system.  Similarly any Resource Server that wants to can check the allowed resource IDs if there are any, but it is not mandatory to do so.

Authorization Code Grant
-------------------------

This is a completely vanilla as per the OAuth2_ spec, but we give a brief outline here for information purposes.

Browser Requests Code: ``GET /oauth/authorize``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*HTML Responses*

* Request: ``GET /oauth/authorize``
* Request Body: some parameters specified by the spec, appended to the query component using the ``application/x-www-form-urlencoded`` format,

  * ``response_type=code``
  * ``client_id=www``
  * ``scope=read write password``
  * ``redirect_uri`` is optional because it can be pre-registered

* Request Header:

  * ``Cookie: JSESSIONID=ADHGFKHDSJGFGF; Path /`` - the authentication cookie for the client with UAA. If there is no cookie user's browser is redirected to ``/login``, and will eventually come back to ``/oauth/authorize``.

* Response Header: location as defined in the spec includes ``access_token`` if successful::

        HTTP/1.1 302 Found
        Location: https://www.cloudfoundry.example.com?code=F45jH

* Response Codes::

        302 - Found

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

An OAuth2_ defined endpoint to provide various tokens and authorization codes.

For the ``vmc`` flows, we use the OAuth2 Implicit grant type (to avoid a second round trip to ``/token`` and so vmc does not need to securely store a client secret or user refresh tokens). The authentication method for the user is undefined by OAuth2 but a POST to this endpoint is acceptable, although a GET must also be supported (see `OAuth2 section 3.1`_).

.. _OAuth2 section 3.1: http://tools.ietf.org/id/draft-ietf-oauth-v2-26.html#rfc.section.3.1

Effectively this means that the endpoint is used to authenticate **and** obtain an access token in the same request.  Note the correspondence with the UI endpoints (this is similar to the ``/login`` endpoint with a different representation).

.. note:: A GET mothod is used in the `relevant section <http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-4.2.1>`_ of the spec that talks about the implicit grant, but a POST is explicitly allowed in the section on the ``/oauth/authorize`` endpoint (see `OAuth2 section 3.1`_).

All requests to this endpoint MUST be over SSL.

* Request: ``POST /oauth/authorize``
* Request query component: some parameters specified by the spec, appended to the query component using the "application/x-www-form-urlencoded" format,

  * ``response_type=token``
  * ``client_id=vmc``
  * ``scope=read write``
  * ``redirect_uri`` - optional because it can be pre-registered, but a dummy is still needed where vmc is concerned (it doesn't redirect) and must be pre-registered, see `Client Registration Administration APIs`_.

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

In addition to the normal authentication of the ``/oauth/authorize`` endpoint described above (cookie-based for browser app and special case for ``vmc``) the UAA offers a special channel whereby a trusted client app can authenticate itself and then use the ``/oauth/authorize`` endpoint by providing minimal information about the user account (but not the password).  This channel is provided so that authentication can be abstracted into a separate "Login" server.  The default client id for the trusted app is ``login``, and this client is registered in the default profile (but not in any other)::

    id: login,
    secret: loginsecret,
    scope: uaa.none,
    authorized-grant-types: client_credentials,
    authorities: oauth.login

To authenticate the ``/oauth/authorize`` endpoint using this channel the Login Server has to provide a standard OAuth2 bearer token header _and_ some additional parameters to identify the user: ``source=login`` is mandatory, as is ``username``, plus optionally ``[email, given_name, family_name]``.  The UAA will lookup the user in its internal database and if it is found the request is authenticated.  The UAA can be configured to automatically register authenicated users that are missing from its database, but this will only work if all the fields are provided.  The response from the UAA (if the Login Server asks for JSON content) has enough information to get approval from the user and pass the response back to the UAA.

Using this trusted channel a Login Server can obtain authorization (or tokens directly in the implicit grant) from the UAA, and also have complete control over authentication of the user, and the UI for logging in and approving token grants.

An authorization code grant has two steps (as normal), but instead of a UI response the UAA sends JSON:

Step 1: Initial Authorization Request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Request: ``POST /oauth/authorize``
* Request query component: some parameters specified by the spec, appended to the query component using the "application/x-www-form-urlencoded" format,

  * ``response_type=code``
  * ``client_id`` - a registered client id
  * ``redirect_uri`` - a redirect URI registered with the client
  * ``state`` - recommended (a random string that the client app can correlate with the current user session)
  * ``source=login`` - mandatory
  * ``username`` - the user whom the client is acting on behalf of (the authenticated user in the Login Server)
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

Step 2: User Approves Grant
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
            "client_id":"vmc"
        }

Notes:

* The ``user_name`` is the same as you get from the `OpenID Connect`_ ``/userinfo`` endpoint.  The ``user_id`` field is the same as you would use to get the full user profile from ``/User``.
* Many of the fields in the response are a courtesy, allowing the caller to avoid further round trip queries to pick up the same information (e.g. via the ``/User`` endpoint).
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

An endpoint which returns login information, e.g prompts for authorization codes or one-time passwords. This allows vmc to determine what login information it should collect from the user.

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

Create a User: ``POST /User``
------------------------------

See `SCIM - Creating Resources`__

__ http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#create-resource

* Request: ``POST /User``
* Request Headers: Authorization header containing an OAuth2_ bearer token with::

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


Update a User: ``PUT /User/{id}``
----------------------------------------

See `SCIM - Modifying with PUT <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#edit-resource-with-put>`_

* Request: ``PUT /User/{id}``
* Request Headers: Authorization header containing an OAuth2_ bearer token with::

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

Change Password: ``PUT /User/{id}/password``
----------------------------------------------

See `SCIM - Changing Password <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#change-password>`_

* Request: ``PUT /User/{id}/password``
* Request Headers: Authorization header containing an OAuth2_ bearer token with::

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

Query for Information: ``GET /Users``
---------------------------------------

See `SCIM - List/Query Resources`__

__ http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#query-resources

Get information about a user. This is needed by to convert names and email addresses to immutable ids, and immutable ids to display names. The implementation provides the core schema from the specification, but not all attributes are handled in the back end at present (e.g. only one email address per account).

Filters: note that, per the specification, attribute values are comma separated and the filter expressions can be combined with boolean keywords ("or" and "and").

* Request: ``GET /Users?attributes={requestedAttributes}&filter={filter}``
* Request Headers: Authorization header containing an OAuth2_ bearer token with::

        scope = scim.read
        aud = scim

* Response Body (for ``GET /Users?attributes=id&filter=emails.value eq bjensen@example.com``)::

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

Delete a User: ``DELETE /User/{id}``
-------------------------------------

See `SCIM - Deleting Resources <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#delete-resource>`_.

* Request: ``DELETE /User/{id}``
* Request Headers: 

  + Authorization header containing an OAuth2_ bearer token with::

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

There is a SCIM-like endpoint for converting usernames to names, with the same filter and attribute syntax as ``/Users``. It must be supplied with a ``filter`` parameter.  It is a special purpose endpoint for use as a user id/name translation api, and is should be disabled in production sites by setting ``scim.userids_enabled=false`` in the UAA configuration. It will be used by vmc so it has to be quite restricted in function (i.e. it's not a general purpose groups or users endpoint). Otherwise the API is the same as /Users.

* Request: ``GET /ids/Users``
* Response Body: list of users matching the filter

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

Create a Group: ``POST /Group``
----------------------------------

See `SCIM - Creating Resources`__

__ http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#create-resource

* Request: ``POST /Group``
* Request Headers: Authorization header containing an OAuth2_ bearer token with::

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
        Location: https://example.com/v1/Group/uid=123456
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

Update a Group: ``PUT /Group/{id}``
----------------------------------------

See `SCIM - Modifying with PUT <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#edit-resource-with-put>`_

* Request: ``PUT /Group/{id}``
* Request Headers: 

  + Authorization header containing an OAuth2_ bearer token with::

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
* Request Headers: Authorization header containing an OAuth2_ bearer token with::

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

Delete a Group: ``DELETE /Group/{id}``
-----------------------------------------

See `SCIM - Deleting Resources <http://www.simplecloud.info/specs/draft-scim-rest-api-01.html#delete-resource>`_.

* Request: ``DELETE /Group/{id}``
* Request Headers: 

  + Authorization header containing an OAuth2_ bearer token with::

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

Access Token Administration APIs
=================================

OAuth2 protected resources which deal with listing and revoking access tokens.  To revoke a token with ``DELETE`` clients need to provide a ``jti`` (token identifier, not the token value) which can be obtained from the token list via the corresponding ``GET``.  This is to prevent token values from being logged in the server (``DELETE`` does not have a body).

List Tokens for User: ``GET /oauth/users/{username}/tokens``
-------------------------------------------------------------

* Request: ``GET /oauth/users/{username}/tokens``
* Request body: *empty*
* Response body: a list of access tokens, *example* ::

        HTTP/1.1 200 OK
        Content-Type: text/plain

        [
          {
            "access_token": "FYSDKJHfgdUydsFJSHDFKAJHDSF",
            "jti": "fkjhsdfgksafhdjg",
            "expires_in": 1234,
            "client_id": "vmc"
          }
        ]

Revoke Token by User: ``DELETE /oauth/users/{username}/tokens/{jti}``
----------------------------------------------------------------------------

* Request: ``DELETE /oauth/users/{username}/tokens/{jti}``
* Request body: *empty*
* Response code: ``200 OK``
* Response body: a status message (hash)

List Tokens for Client: ``GET /oauth/clients/{client_id}/tokens``
---------------------------------------------------------------------

* Request: ``GET /oauth/clients/{client_id}/tokens``
* Request body: *empty*
* Response body: a list of access tokens, *example* ::

        HTTP/1.1 200 OK
        Content-Type: text/plain

        [
          {
            "access_token": "KJHDGFKDHSJFUYTGUYGHBKAJHDSF",
            "jti": "fkjhsdfgksafhdjg",
            "expires_in": 1234,
            "client_id": "www"
          }
        ]

Revoke Token by Client: ``DELETE /oauth/clients/{client_id}/tokens/{jti}``
--------------------------------------------------------------------------------

* Request: ``DELETE /oauth/clients/{client_id}/tokens/{jti}``
* Request body: *empty*
* Reponse code: ``200`` OK
* Response body: a status message (hash) ::

        HTTP/1.1 200 OK
        { "status": "ok" }

Get the Token Signing Key: ``GET /token_key``
-----------------------------------------------

An endpoint which returns the JWT token key, used by the UAA to sign JWT access tokens, and to be used by authorized clients to verify that a token came from the UAA.

This call is authenticated with client credentials using the HTTP Basic method.

================  ==========================================
Request           ``GET /token_key``
Request body      *empty*
Response body     *example* ::

                    HTTP/1.1 200 OK
                    Content-Type: text/plain

                    {alg:HMACSHA256, value:FYSDKJHfgdUydsFJSHDFKAJHDSF}

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
                  {foo: {
                    client_id : foo,
                    scope : [uaa.none]
                    resource_ids : [none],
                    authorities : [cloud_controller.read,cloud_controller.write,scim.read],
                    authorized_grant_types : [client_credentials]
                  },
                  bar: {
                    client_id : bar,
                    scope : [cloud_controller.read,cloud_controller.write,openid],
                    resource_ids : [none],
                    authorities : [uaa.none],
                    authorized_grant_types : [authorization_code]
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
                    client_id : foo,
                    scope : [uaa.none],
                    resource_ids : [none],
                    authorities : [cloud_controller.read,cloud_controller.write,scim.read],
                    authorized_grant_types : [client_credentials]
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
      client_id : foo,
      client_secret : fooclientsecret, // optional for untrusted clients
      scope : [uaa.none],
      resource_ids : [none],
      authorities : [cloud_controller.read,cloud_controller.write,openid],
      authorized_grant_types : [client_credentials],
      access_token_validity: 43200
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
      client_id : foo,
      scope : [uaa.none],
      resource_ids : [none],
      authorities : [cloud_controller.read,cloud_controller.write,openid],
      authorized_grant_types : [client_credentials]
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
      oldSecret: fooclientsecret,
      secret: newclientsceret
    }

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
