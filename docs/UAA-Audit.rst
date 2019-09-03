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

* UserAuthenticationSuccess
    - Happens: When a user is successfully authenticated
    - Data Recorded: User ID and Username

* UserAuthenticationFailure
    - Happens: When a user authentication fails, user exists
    - Data Recorded: Username
    - Notes: Followed by a PrincipalAuthenticationFailureEvent

* UserNotFound
    - Happens: When a user authentication fails, user does not exists
    - Data Recorded: Username
    - Notes: Followed by a PrincipalAuthenticationFailureEvent

* UnverifiedUserAuthentication
    - Happens: When a user that is not yet verified authenticates
    - Data Recorded: User ID, Username

* PasswordChangeSuccess
    - Happens: When a user password is changed through /Users/{user_id}/password
    - Data Recorded: User ID

* PasswordChangeFailure
    - Happens: When a user password change is attempted through /Users/{user_id}/password
    - Data Recorded: User ID

* ClientAuthenticationSuccess
    - Happens: When a client is successfully authenticated
    - Data Recorded: Client ID

* ClientAuthenticationFailure
    - Happens: When a client authentication fails (client may or may not exist)
    - Data Recorded: Client ID

* PrincipalAuthenticationFailure
    - Happens: When a client or user authentication fails
    - Data Recorded: Client ID or Username

* PrincipalNotFound
    - Happens: currently not used
    - Data Recorded:

* PasswordResetRequest
    - Happens: When a user requests to reset his/her password
    - Data Recorded: Email used

* IdentityProviderAuthenticationSuccess
    - Happens: When a user successfully authenticates for the password login
    - Data Recorded: User ID and Username

* IdentityProviderAuthenticationFailure
    - Happens: When a user authentication fails for the password login, and user exists
    - Data Recorded: User ID
    - Notes: Followed by a UserAuthenticationFailureEvent and PrincipalAuthenticationFailureEvent

* MfaAuthenticationSuccess
    - Happens: When a user successfully authenticates with MFA
    - Data Recorded: User ID, Username and MFA type (e.g. google-authenticator)

* MfaAuthenticationFailure
    - Happens: When a user enters an incorrect code for MFA
    - Data Recorded: User ID, Username and MFA type (e.g. google-authenticator)

Scim Administration Events
==============================================================

* UserCreatedEvent
    - Happens: When a user is created
    - Data Recorded: User ID (user_id), Username (username), User Origin (user_origin)
    - Notes: When the user is created by a client, also records the client ID (created_by_client_id).
      When the user is created by another user, also records the User ID (created_by_user_id) and Username (created_by_username) of the user who performed the creation.

* UserModifiedEvent
    - Happens: When a user is modified
    - Data Recorded: User ID, Username

* UserDeletedEvent
    - Happens: When a user is deleted
    - Data Recorded: User ID (user_id), Username (username), User Origin (user_origin)
    - Notes: When the user is deleted by a client, also records the client ID (deleted_by_client_id).
      When the user is deleted by another user, also records the User ID (deleted_by_user_id) and Username (deleted_by_username) of the user who performed the deletion.

* UserVerifiedEvent
    - Happens: When a user is verified
    - Data Recorded: User ID, Username

* EmailChangedEvent
    - Happens: When a user email is changed
    - Data Recorded: User ID, Username, updated Email

* ApprovalModifiedEvent
    - Happens: When approvals are added, modified or deleted for a user
    - Data Recorded: Username, Scope and Approval Status

* GroupCreatedEvent
    - Happens: When a group is created
    - Data Recorded: Group ID, Group Name, Members

* GroupModifiedEvent
    - Happens: When a group is updated (members added/removed)
    - Data Recorded: Group ID, Group Name, Members

* GroupDeletedEvent
    - Happens: When a group is deleted
    - Data Recorded: Group ID, Group Name, Members

Token Events
==============================================================

* TokenIssuedEvent
    - Happens: When a token is created
    - Data Recorded: Principal ID (client or user ID), scopes


Client Administration Events
==============================================================

* ClientCreateSuccess
    - Happens: When a client is created
    - Data Recorded: Client ID, Scopes, Authorities

* ClientUpdateSuccess
    - Happens: When a client is updated
    - Data Recorded: Client ID, Scopes, Authorities

* SecretChangeFailure
    - Happens: When a client secret fails to change
    - Data Recorded: Client ID

* SecretChangeSuccess
    - Happens: When a client secret is changed
    - Data Recorded: Client ID

* ClientApprovalsDeleted
    - Happens: When all approvals for a client are deleted
    - Data Recorded: Client ID

* ClientDeleteSuccess
    - Happens: When a client is deleted
    - Data Recorded: Client ID


UAA Administration Events
==============================================================

* ServiceProviderCreatedEvent
    - Happens: When managing the details of an external service provider which uses the UAA as a SAML IDP
    - Data Recorded: Principal ID (client or user ID), Service Provider

* ServiceProviderModifiedEvent
    - Happens: When managing the details of an external service provider which uses the UAA as a SAML IDP
    - Data Recorded: Principal ID (client or user ID), Service Provider

* IdentityZoneCreatedEvent
    - Happens: When identity zone is created in the UAA
    - Data Recorded: Principal ID (client or user ID), Identity Zone

* IdentityZoneModifiedEvent
    - Happens: When managing the configuration of identity zones in the UAA
    - Data Recorded: Principal ID (client or user ID), Identity Zone

* IdentityProviderCreatedEvent
     - Happens: When configuring the UAA to authenticate with an external IDP such as SAML or LDAP
     - Data Recorded: Principal ID (client or user ID), Identity Provider

* IdentityProviderModifiedEvent
     - Happens: When configuring the UAA to authenticate with an external IDP such as SAML or LDAP
     - Data Recorded: Principal ID (client or user ID), Identity Provider

* EntityDeletedEvent
     - Happens: When an identity provider or identity zone is deleted
     - Data Recorded: Principal ID (client or user ID), Deleted entity

Flows
==============================================================

Below are some example flows for a UAA configured with LDAP as an IDP

* Browser flows
     - Successful login: UserNotFound -> PrincipalAuthenticationFailure -> UserCreatedEvent -> IdentityProviderAuthenticationSuccess -> UserAuthenticationSuccess
     - Invalid password: UserNotFound -> PrincipalAuthenticationFailure -> IdentityProviderAuthenticationFailure
     - Unknown user: UserNotFound -> PrincipalAuthenticationFailure -> IdentityProviderAuthenticationFailure

* Password grant
     - Successful login: ClientAuthenticationSuccess -> UserNotFound -> PrincipalAuthenticationFailure -> IdentityProviderAuthenticationSuccess -> UserAuthenticationSuccess -> TokenIssuedEvent
     - Invalid password: ClientAuthenticationSuccess -> UserNotFound -> PrincipalAuthenticationFailure -> IdentityProviderAuthenticationFailure
     - Unknown user: ClientAuthenticationSuccess -> UserNotFound-> PrincipalAuthenticationFailure -> IdentityProviderAuthenticationFailure
