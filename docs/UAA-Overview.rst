==================================================
User Account and Authentication Service Overview
==================================================

.. contents:: Table of Contents

Goals of Standards-based Identity Services for Cloud Foundry
==============================================================

There are two major goals of standards-based authentication services for Cloud Foundry. Both of these goals could be achieved by using standards-based authentication protocols in a proposed User Account and Authentication component (UAA) for Cloud Foundry.

Incoming Authentication
------------------------

UAA would store user accounts that would include some profile information for use by Cloud Foundry support applications. However, the UAA should support external authentication services. In other words, a cloud foundry instance should be able to authenticate a user using other mechanisms than an internally stored username and password. Those external authentication mechanisms should be based on standards such as LDAP, OpenID, and SAML2. Support for external authentication via those protocols would mean that a user could use authentication sources such as:

#. Their Google, Twitter, or Facebook accounts via OAuth and OpenID.
#. A corporate Active Directory instance via LDAP (assuming the CF instance has access to AD, e.g. Bento).
#. A corporate Active Directory instance through Horizon's rules engine for dynamic entitlements and group membership via SAML or OAuth2.
#. A multi-factor or smart card authentication system attached to a corporate SAML2 identity provider such as ADFS, Ping Federate, Novell or Oracle Access Manager.

Outgoing Authentication
------------------------

The cloudfoundry.com and cloudfoundry.org sites include a number of applications that support the Cloud Foundry community. Some of these applications run on the cloudfoundry.com PaaS itself. Some of them, like support.cloudfoundry.org run on other infrastructure. It would be the best experience if users could have a single-sign-on capability among all these applications. Furthermore, the authentication to the applications should be based on one standard protocol from the UAA -- even though authentication to the UAA may use authentication sources external to cloudfoundry.com such as Horizon Access Manager, Facebook Connect, or Google Accounts.

Current expectation is that that protocol will be OpenID Connect (which includes OAuth2).

OpenID Connect and OAuth2
----------------------------

Two standards that best achieve the goals above are OAuth2 and OpenIDConnect.

OAuth2_ is a standard from the IETF and is nearing completion at the time of this writing. More information can be found at http://oauth.net/2.

.. _OAuth2: http://tools.ietf.org/html/draft-ietf-oauth-v2

`OpenID Connect`_ is a successor to OpenID 2.0 and combines a number of fragmented specifications such as the original OpenID Connect, OpenID v.next, OpenID AB (Artifact Binding) and others. It builds on OAuth2_ to specify how proof of authentication and other identity can be handled within an OAuth2 system.

A good very high level description of OpenID Connect relative to OAuth2 by the co-editor of the OpenID Connect specification is http://nat.sakimura.org/2011/05/15/dummys-guide-for-the-difference-between-oauth-authentication-and-openid

There is also a high-level overview of the suite of `OpenID Connect`_ specifications, complete with a clickable map.

.. _OpenID Connect: http://openid.net/connect

OAuth2_ includes bindings for other authentication methods to use with OAuth2 such as SAML bearer tokens, MAC, etc. The set of specifications can be found here: http://tools.ietf.org/wg/oauth.

The Cloud Foundry UAA component will implement the OAuth2_ and `OpenID Connect`_ standards, which should allow sufficient flexibility to plug in other external authentication systems such as Kerberos (via Horizon), SAML, multi-factor with no change to the connected applications.

Cloud Foundry User Account and Authentication Service
======================================================

The user account and authentication service running on cloudfoundry.com needs to hold the database of Users described in the Collaborations Spaces document, but otherwise can run as a fairly loosely coupled service. The authentication service does not give the applications running on cloudfoundry.com or cloudfoundry.org access to the user account database, it only provides authentication information to those applications via OpenID Connect (and, therefore, OAuth2).

To comply with the OAuth2 standard, interactions with the Authentication Service will need to be over an SSL connection.

Applications and Implementation Concerns
=========================================


The current applications under consideration for the authentication service with status and concerns are listed below.

api.cloudfoundry.com
---------------------

The cloud foundry service itself would use the UAA service. The OAuth access token would be used instead of the current token in a similar way. Possible APIs and component boundaries between the UAA, the colloboration spaces authorization system, and the cloud controller are currently being explored in POC code. 

www.cloudfoundry.com
----------------------

Current thought is that the www site could be the UI for the user account and authentication service. It would support user account creation and management such as password reset, etc. This is also where any OAuth2 authorization page would go if we were to allow users to authorize other applications to access portions (scopes) of the cloudfoundry APIs on their behalf.

The www app also supports the microcloud DNS management which would need to support OAuth2 access tokens as a client of the UAA.

studio.cloudfoundry.com
-------------------------

Since CF Studio is a web application, it can use the OAuth2 redirect flows and therefore get an access token for its users via SSO with the UAA. Current expectation is that it would not be difficult for them to implement an OAuth client in their application such that their users would get SSO with VMware applications on cloudfoundry.com.

support.cloudfoundry.com
--------------------------

The product already supports various flavors of OpenID and OAuth, though status of OpenID Connect support is unknown.

Unresolved Issues
===================

OAuth2 Scopes
--------------

Not so much unresolved as just postponed. OAuth2 lets an authorization provider designate scopes that can further restrict what access a user delegates. For example, when I hear of a new app that can analyze my apps on cloud foundry, I may only want to authorize it to read my data, not make any changes.

Interaction between Collaboration Spaces and External Groups used for Authorization
------------------------------------------------------------------------------------

In the collaboration spaces design, a group may indicate that its membership is determined by an external source, such as a Group in Active Directory or a dynamic group in Horizon App Manager (which would be part of a SAML assertion). How is that information gathered by the UAA and provided to the Collaboration Spaces code?

One or More External Authentication Mechanisms for Users
----------------------------------------------------------------------

If I have an account in a cloudfoundry instance and work on projects within multiple orgs, what happens if they have differing authentication policies? If the UAA allows me to have multiple authentication sources, I would need to sometimes re-authenticate when targeting a new Org. 

