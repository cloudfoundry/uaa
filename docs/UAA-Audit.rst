==================================================
User Account and Authentication Service Audit Requirements
==================================================

.. contents:: Table of Contents

Overview
==============================================================

The User Account and Authentication Service (UAA):

* Handles authentication for users and client applications
* Manages user accounts
* Manages client application registrations

Each audit event must at a minimum contain

  * Client Address - the client IP or if not attainable, the IP of the last proxy
  * Date/Time of the event
  * Principal - if authenticated
  * Client ID

  * Authorization type (basic,token)
  * Path - the request path
  * Result Status Code

Events
==============================================================

UserAuthenticationSuccessEvent - when user logs in
UserAuthenticationFailureEvent/PrincipalAuthenticationFailureEvent - invalid user password
UserNotFoundEvent/PrincipalAuthenticationFailureEvent - invalid user id
PasswordChangeEvent - password successfully changed for a user
PasswordChangeFailureEvent - password failed to change for a user
ClientAuthenticationSuccessEvent - client authentication
ClientAuthenticationFailureEvent - client authentication



Urls to denote for auditing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/oauth/authorize
 grant_type
 scope
 result

/oauth/authorize?user_oauth_approval=true
 grant_type
 scope
 result
 approvals

GET /oauth/authorize/confirm_access

/oauth/token
 credentials or code
 result - access token?

/check_token

/check_id

/userinfo

POST /Users
  Create User Event

PUT /Users/{userid}
  Update User Event

PUT /Users/{id}/password
  Password Change Event

GET /Users/{id}/verify
  User verified event

GET /Users
  Query User Event - query

DELETE /Users/{id}
  Delete user event

GET /ids/Users

POST /Group
  Create group event

PUT /Group/{id}
  Update group event

GET /Groups
  Query groups event

DELETE /Group/{id}
  Delete group event

DELETE /oauth/users/{username}/tokens/{jti}
  Delete tokens event

DELETE /oauth/clients/{client_id}/tokens/{jti}
  Delete tokens event

GET /token_key
  Retrieve Token Key event

POST /oauth/clients/{client_id}
PUT /oauth/clients/{client_id}
DELETE /oauth/clients/{client_id}
PUT /oauth/clients/{client_id}/secret
POST /oauth/clients/tx
PUT /oauth/clients/tx
POST /oauth/clients/tx/modify
POST /oauth/clients/tx/secret
POST /oauth/clients/tx/delete

POST /login.do
GET /logout.do

