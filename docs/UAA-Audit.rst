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

Each audit event contains

  * Client Address - the client IP or if not attainable, the IP of the last proxy
  * Date/Time of the event
  * Principal - if authenticated
  * Client ID - if available
  * Data identifying the event

Authentication and Password Events
==============================================================

* UserAuthenticationSuccessEvent
    - Happens: When a user is successfully authenticated
    - Data Recorded: User ID and Username

* UserAuthenticationFailureEvent
    - Happens: When a user authentication fails, user exists
    - Data Recorded: Username
    - Notes: Followed by a PrincipalAuthenticationFailureEvent

* UserNotFoundEvent
    - Happens: When a user authentication fails, user does not exists
    - Data Recorded: Username
    - Notes: Followed by a PrincipalAuthenticationFailureEvent

* PasswordChangeEvent
    - Happens: When a user password is changed through /Users/{user_id}/password
    - Data Recorded: User ID

* PasswordChangeFailureEvent
    - Happens: When a user password change is attempted through /Users/{user_id}/password
    - Data Recorded: User ID

* ClientAuthenticationSuccessEvent
    - Happens: When a client is successfully authenticated
    - Data Recorded: Client ID

* ClientAuthenticationFailureEvent
    - Happens: When a client authentication fails (client may or may not exist)
    - Data Recorded: Client ID

* PrincipalNotFoundEvent
    - Happens: currently not used
    - Data Recorded:

* ResetPasswordRequestEvent
    - Happens: When a user requests to reset his/her password
    - Data Recorded: Email used

Scim Administration Events
==============================================================

* UserModifiedEvent
    - Happens: When a user is created, modified, verified or deleted
    - Data Recorded: User ID, Username

* ApprovalModifiedEvent
    - Happens: When approvals are added, modified or deleted for a user
    - Data Recorded: Username, Scope and Approval Status

* GroupModifiedEvent
    - Happens: When a group is created, updated (members added/removed) or deleted
    - Data Recorded: Group ID, Group Name, Members

Token Events
==============================================================

* TokenIssuedEvent
    - Happens: When a token is created
    - Data Recorded: Principal ID (client or user ID), scopes


Client Administration Events
==============================================================

* ClientCreateEvent
    - Happens: When a client is created
    - Data Recorded: Client ID

* ClientUpdateEvent
    - Happens: When a client is updated
    - Data Recorded: Client ID

* SecretFailureEvent
    - Happens: When a client secret fails to change
    - Data Recorded: Client ID

* SecretChangeEvent
    - Happens: When a client secret is changed
    - Data Recorded: Client ID

* ClientApprovalsDeletedEvent
    - Happens: When all approvals for a client are deleted
    - Data Recorded: Client ID

* ClientDeleteEvent
    - Happens: When a client is deleted
    - Data Recorded: Client ID

