================================================
CloudFoundry Identity Services Preface
================================================

.. attention:: This document was written in the summer of 2011. Many of the principles and goals are still valid in Dec 2011, but it has not been updated for some time. 

.. contents:: Table of Contents

Introduction and Disclaimer
--------------------------------------------------

We have too damn many user accounts and passwords.

It's beyond inconvenient. It's slowing us down while causing us to lose control of our own work.

More significant for developers, it's too difficult to create applications that provide secure, controlled access for their users without creating yet more damn user accounts with passwords.

The intent of this document is to provide an overall context in which to explore a consistent and comprehensive strategy for Cloud Foundry identity services. It covers how that strategy affects developers using Cloud Foundry, the users of their applications, and the Cloud Foundry community. The strategy should specify core structures and capabilities as well as extension points for the community.

This document is obviously a work in progress. It's an attempt to organize and structure some initial research and ideas. 

Goals of Cloud Foundry Identity Services
---------------------------------------------

There are three goals of this phase of the identity services for cloud foundry, in order of priority:

Provide user authentication and authorization for the Foundry platform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Developers and administrators should have secure and convenient access to the Foundry platform itself. This includes being able to use an external user account for authentication rather than storing a password in a Foundry account. Authorization for some tasks should also be able to be given to others, i.e. delegated administration.&nbsp; Authorization should also be able to be revoked, causing access to be subsequently denied across the various Foundry components.

Access to the platform occurs through a variety of methods, including command line tools and desktop applications, so the authentication mechanism must work for these clients as well as browsers.

This general concept of supporting policies and roles within CloudFoundry itself is clearly needed for application developers so that they can development teams can produce, deploy and manager applications. This concept is referred to in CloudFoundry code and internal design documents as Collaboration Spaces.

Provide identity services to Cloud Foundry applications
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Foundry applications need a variety of identity services, yet the services need to be provided in an easily accessible, simple manner or developers tend to implement their own simple -- often insecure and inflexible -- solutions.

Some identity services that should be easily available to Foundry applications:

* Applications should be able to simply choose from a number of external identity sources.
* External identity sources should be accessible via federated identity protocols with no impact on the application developer.&nbsp;
* Applications should be able to easily connect to a user account service to store application specific data and/or passwords.
* For API level access, applications should be able to simply request or validate authorization tokens from the identity service without requiring access to the users password.
* User authentication, authorization, and account information should be able to associated with the user's session within each existing application framework.

All identity services should be able to support multi-tenant applications (i.e. where users within the application come from multiple identity providers).

Apply Foundry identity services to support the Cloud Foundry community
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Developers interact with the Foundry platform and with each other to form the Foundry community. The community uses tools such as git, github, wikis, mailing lists, and IRC channels, as well as accessing the Foundry platform.&nbsp; The current tools often use completely disjoint user accounts, and can lack authorization controls to enable maximum openness while maintaining necessary control to insure stable progress.

Our Foundry Identity Services strategy should be able to be applied to the Foundry Community tools to enhance the development process. For example, we should be able to reduce friction for developers to contribute to the community in an effective and yet controlled and stable way.

Interestingly, this goal is effectively a use case that can be used to drive some of the requirements for the previous goals.

Design Principles
---------------------------------------------

A few appropriate principles to guide the rest of the strategy, in random order:

Eat our own identity services
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Effectively we should focus on the goal to "Provide Identity Services to Foundry Applications". Access to the Cloud Foundry itself can be seen (mostly) as access to the initial application. Likewise, using our identity services within applications to enhance the interaction of the Foundry Community can be a great use case to drive and validate requirements for the services.

Reusing other user accounts should be easy -- Federation should be easy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When applying the general principle of "simple things should be easy, difficult things should be possible" to an authentication service, the simplest thing should be for an app to use external, pre-existing accounts. For most simple applications this means there is less friction for new users, and more security. Creating user accounts with passwords, captchas, and email verification should be possible.

Identity services should be pluggable
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

One of Cloud Foundry's strengths is its support for extensible services. Wherever possible, the identity services should use this feature to support pluggable authentication and user account services.

Support delegation of user access from one app to another
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Many cloud applications now, and even more in the future, will combine their internal data and processing with that of other applications and services across the Internet.

Web Apps running on Cloud Foundry should not have to implement an authentication UI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are many types and needs implemented in numerous authentication methods: username/password, one time password (OTP) from device, smart card, OTP to phone, multi-factor, etc. Tenants within a single application will need to use different methods. To provide necessary security and flexibility, the identity provider must be able to specify the authentication UI. For web applications this is done through browser redirects.&nbsp; For non-web applications, we will need to come up with something else.

Components and Functional Description
---------------------------------------------


Overview
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Overview and block diagram here showing major component and plugin points.

Identity Services Core
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Most important service is coordinating authentication, authorization, and account services with applications. Other possible core services:

* OAuth services for AuthServer, Client, ResourceServer
* Public key store and signing service

Account Services
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Support plugin for identity account system. Account system should provide persistent storage for user information, whether or not passwords are used. Should be able to support provisioning and schema similar to SCIM. User accounts should be able to be connected to the session management system within each framework.

Authentication Services
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Support plugin for authentication system. By supporting plugins we can provide direct authentication services via LDAP or Foundry account services, or federated authentication via OpenID, OAuth, or SAML, but not every application has to carry support for all authentication types. &nbsp;

Current expectation is that this service will need to have some interaction with the application's login screen -- either by providing some javascript code to the application or redirecting to code in the framework. After that, the application uses session capabilities of the framework.&nbsp;

Authorization Services
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Support plugin for authorization services. This would be particularly useful to call out to Horizon Access Manager.

Developer Perspective
---------------------------------------------


The simple case
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Simple case should be external identity sources such as Google Accounts, Facebook, Horizon Access Manager. Developer connects to authentication service, injects javascript snippet into login page. Done.

Difficult cases
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To have more control over login sequence than the simple case, the developer will need to separate redirection to IdP from callback to get identity token. See OmniAuth.

Multi-tenancy, especially IdP discovery.

Easy registration via OpenID or OAuth, then separate accounts.

Support for multiple authentication sources per account.

Lots more variations, external authorization issues, etc.

End User Perspective
---------------------------------------------

What it looks like to a user ...

From the browser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Easy case, redirection, javascript chunks, etc.

Options for non-browser applications
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some companies, e.g. Salesforce, and standardizing on launching a browser in all cases, then redirecting back to the native app using a special HTTP scheme.

OAuth2 supports a flow where an access code can be obtained and typed in.

Just an idea -- perhaps we could support an IdP specified list of named fields to collect on the command line and pass to the backend (or pass a hashed value). This would handle many cases such as username/password‚ OTP, number sent to phone, etc. The problem is that this will still ultimately fail for some authentication methods, e.g. graphical or biometric.

Securing Developer Access to the Foundry Platform
---------------------------------------------------

How identity services would be applied to the cloud foundry itself.

Need support for non-browser native apps such as cf. Options:

* like the mobile app flow‚ pop up browser and redirect
* if no redirect possible, oauth2 supports a flow where an access code can be obtained and typed in
* support username/password as a fall back -- if we can show easy, more convenient options‚
* perhaps just specify a list of named fields to pass to backend \-\- OTP, number sent to phone, etc

Supporting Collaboration within the Foundry Community
-------------------------------------------------------

How identity services could be applied to the Cloud Foundry Community itself.

Hypothetically speaking how these identity services could be applied to GitHub, git, irc, twitter, wiki, www.cloudfoundry.org?

Not hypothetically speaking, what can we do to make things better now with an evolutionary approach? Perhaps by combining some apps running on CloudFoundry, CloudFoundry itself, and integrating with some of the external collaboration systems via Horizon Access Manager.

Integration with Horizon Access Manager
---------------------------------------------

Should be very simple out-of-the-box one-click integration to support for external federation system, rules engine, etc., of Horizon Access Manager.

Relevant Standards
---------------------------------------------


OAuth2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The OAuth 2 RFC from the IETF should be complete this summer. A number of companies such as Google, Microsoft, Facebook, Salesforce have already implemented early versions of the RFC.

http://oauth.net/2/

OpenID Connect
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenID has been somewhat stagnant since OpenID 2.0 was completed. The community fragmented over competing future directions in efforts such as OpenID Connect, OpenID Artifact Binding, etc. These issues appear to be resolved as of early May 2011. The combined efforts are now called OpenID Connect (though developed in the OpenID AB working group), and will be built on top of the OAuth 2 RFC.

http://lists.openid.net/mailman/listinfo/openid-specs-ab

System for Cross-domain Identity Management (SCIM)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A new effort led by Salesforce, Ping Identity, others, attempting to produce a REST/JSON standard for managing user accounts, attributes, roles, groups. LDAP for cloud apps.

http://www.simplecloud.info/


