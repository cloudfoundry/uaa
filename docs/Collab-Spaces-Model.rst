============================
Collaboration Spaces Model
============================

.. attention:: This document was current as of Sept 2011 and has been superseded by the Access Control Manager documentation 
   referred to in the UAA-CC-ACM-VMC-Interactions document as of Nov 2011. However, many of the requirements, principles and 
   goals of this document are still valid and are left here until this document is refactored into a new form. 

.. contents:: Table of Contents

Introduction
================

This document describes an evolving model for how roles based access and collaboration spaces could be implemented in Cloud Foundry. The initial very high level goals are to:

#. Support a natural evolution from the current access control system
#. Preserve simple initial usage for developers
#. Allow more complex controls to be specified when needed
#. Define a fluid organizational system that allows for multiple overlapping collaboration spaces. These spaces provide a context to control access to resources. They are meant to behave more like containers for roles and resources that map to how people work rather than a rigid hierarchy of resources with access control lists.

We will discuss requirements, the major elements of the model, and then how it applies to some known Cloud Foundry use cases. Finally, there is a list of unresolved issues and some discussion of each.

Requirements and Use Cases
============================

A list of requirements in approximate priority order:

#. Separation of duties
    I should be able to pick whether I am operating in a super admin role that can delete a production app, or a role where I can safely play with a new app. I should be able to set a context so that I am restricted to access rights to an area such as my demo apps and can't accidentally delete the apps and services that are out of that scope.

#. Collaboration spaces for humans
    It should be easy to manage a set of resources with individuals and groups in various roles and access permissions. Traditional groups and hierarchical objects with ACLs tend to be complex and counter intuitive. In Cloud Foundry we'd like collaboration spaces to be structured more how people naturally work. We want to structure management of resources around the notion of collaboration spaces -- where users and groups are defined to be in various roles which determine access to resources.

#. Compatibility with current usage for developers
    Preserve simplicity of current use model for new and existing users. Only add complexity of collaboration spaces roles and permissions when needed.

#. Constrained delegation of administration
    I should be able to set up access control so that a group of people can be self-managing, i.e. specify who is in the group or role, delegate permissions, etc. yet they should only be able to manage limited delegation of permissions. For example, a group should be able to monitor all resources in an organization and manage their own team membership, but cannot grant themselves create, delete, update permissions to any resources, etc.

#. Permissions not levels
    Many systems specify roles that are really levels of control such as auditor (read-only), developer (read + update), admin (read + update + delegation). The problem is that there are really separate roles and duties involved. I should be able to specify that I want to use my admin permissions to modify who can access and control specific resources, and yet not have that permission mean that I can update a resource. Of course, if I can grant permissions then I could always give myself permissions to update or delete any resource, but I'd have to specifically grant those permissions. In other words, there should be no "Admin" role that automatically gets modification permissions to all resources. Administering access to resources is an independent permission from permissions on that resource.

#. CRUD instead of R/W
    A common request is that a developer or admin should be able to update a resource, but that deleting the resource should be a separate permission. That way a developer can be given permission to update an application, but a much smaller set of users can actually delete an application. A similar case can be made that Create should be a separate permission from Write. IOW, separate Create, Update and Delete permissions rather than a single Write permission.

#. Quickly eliminate permissions of deleted users
    It should be easy to remove all permissions granted to a user within an organization. For example, when a user leaves a company that is a tenant of cloud foundry, all permissions for that user need to be easily identified and eliminated.

#. Provide authorization information for services external to the Cloud Controller
    Cloud Foundry instances should be able to add new services which can authorize new actions without requiring an update to the central authorization service. Right now all vmc commands are understood by the cloud controller. New services will support actions that the cloud controller knows nothing about, and should know nothing about. The collaboration spaces authorization service should be able to authenticate users and calculate authorization information to send to those services, with the action string, and let the service make the authorization decision.

#. Move resources between organizations
    This is likely a long term need and is certainly a short term need as we move from single-user system to organizations for collaboration spaces.

#. Horizon Application Manager integration
    Users of Cloud Foundry should be able to make use of the Horizon enterprise integration and sophisticated policy calculations to control authorization to cloud foundry actions.

#. Simple collaboration model
    The model needs to be simple, or at least have simplified interfaces for easy small group collaboration, open source project use. Preferably not 3 levels of nested spaces, no hierarchical projects, etc.

#. Multiple user accounts for the same email address
    I should be able to set up test and demo accounts, accounts for other purposes within an organization, and for use in other organizations without having to use a separate email address for each.

#. Calculate effective permissions
    There are various circumstances where it is important to be able to calculate whether an action would be permitted without actually requesting the action. For example, a UI may want to gray out some options that a user is not authorized to perform.

#. Show permission aggregation
    In authorization systems that involve indirect references to users such as organizations, groups, and ACLs with various permissions, it can sometimes be difficult to understand why a permission is granted or denied to a specific user. The authorization service should support a query that helps to explain how permissions are calculated for a specific user, resource and action.

Major Elements
===============

The major elements of the model are described below. These elements are expected to be represented in the Cloud Controller database, though there remain some unresolved issues regarding whether multiple layers of physically separate databases would be needed.

.. note:: There is talk of splitting authentication, authorization, and the collaboration model into a new cloud foundry component. This way the component would own the model, and then interact with cc in a more formal way, similar to how the new health manager will interact.


Cloud Foundry Instance
------------------------

A Cloud Foundry Instance (CFInstance) is a deployment of Cloud Foundry code such as cloudfoundry.com or within an enterprise via Bento. The remaining elements operate within the scope of a single CFInstance -- i.e. all Orgs, Users, Groups, Projects, Resources, Permission and Action Sets -- are described within a database in the CFInstance. There are various operational Groups and Projects within that instance that are automatically generated. Starting from those operational elements, the system can be configured for the needs of various roles like application developers and system-wide monitors. These differing needs are addressed by various combinations of the elements below.

Org
------

An org owns resources such as services and applications, therefore an org is the unit of billing and domain name mapping. In the predominant SaaS meaning of multi-tenancy, an org is a tenant. While it does not contain the user accounts themselves, an org does control all user access to the org's resources. It controls which users can interact with its resources, where the user accounts come from, how they can authenticate, and what actions they can perform.

Orgs contain resources such as groups, projects, applications, services, permission and action sets as defined below. When an org is deleted, its resources (applications, services, groups, projects) are deleted.

When a user is created a personal org for that user is automatically created. *One implication of this is that Org and Users share a name space, i.e. an Org and a User cannot both have the same name.* Another way of looking at it is: an org is essentially a user with some extra information and potentially some additional capacity and/or features enabled.  Multi-user orgs must be created through an interaction with an as yet un-designed part of the Cloud Foundry instance. For example, this would be something like a web interface that accepts payment from a user before creating a multi-user org.

An org should be able to specify how its users can authenticate. In the case of cloudfoundry.com, an org may be configured so that each user can specify their own authentication preference such as username/password, or external identity source such as Google Accounts, or Twitter. In the case of a CFInstance in the enterprise, the org may specify that user authentication must be via username/password checked with an AD instance, or by federating with specific ADFS instance.

User
--------

User accounts exist in the Cloud Foundry Instance but are not contained by an org. In other words, a user can participate in multiple orgs from a single account. Also, users may specify their authentication methods such as LDAP authentication or federated authentication such as SAML2, OAuth, OpenID from some other identity source. When they target a particular org, their authentication policy is calculated so that they can authenticate with an acceptable method at login time.User accounts have the following fields:

* ID
    an immutable numeric identifier assigned by the CFInstance when the account is created.

* User Name
    must be unique within the CFInstance. Used as a display name when referencing the user in groups, projects, etc. May be a login name depending on the authentication method.

* Email Addresses
    one or more email addresses that the user can use to regain control of the account. These do not need to be unique per user. A user should be able to have more than one account with the same email address.

* Authentication sources
    may be a username/password or it may list one or more external authentication sources and a protocol such as LDAP, OpenIDConnect, OAuth (Twitter, Facebook, etc), SAML.

Other fields may be added. Since these user accounts may be used by other applications within the CFInstance via OpenIDConnect, additional fields should follow this schema where possible: http://openid.net/specs/openid-connect-userinfo-1_0.html

Resource
----------

A Resource is something for which we need to control access, such as applications, services, groups and projects. These are named, created and deleted by users within an org. Resources share a single name space within an org, i.e. a service and a group cannot have the same name. Some resource names are reserved for use in access control lists, i.e. resources cannot be named "acls", "apps", "services", "projects", or "groups".

Group
------

Groups are a resource within an org that contain a name, a description, and a set of members. Creation, deletion, and modification of the group is controlled by project access control lists. A group can also be configured such that its member list comes from an external source such as an LDAP directory or as an attribute in a user authentication token. For example, an org may specify that members of a SupportStaff group in their AD instance may have read-only access to all resources in the PublicApplication project. Or an org may specify that all users must use SAML authentication and their group membership is included in the SAML assertion -- this would be particularly useful for Horizon Application Manager integration.

Project
---------

A project is owned by an org. It is essentially an access control list (ACL) that maps a project specific role to a set of users and groups and a set of permissions-resource pairs. It controls permissions to resources which could be applications, services, groups, the project itself, or portions of the project ACLs. The primary reason for there to be multiple projects within an org is so that orgs can support multiple common resources, yet users can specify a subset of their permissions while operating on a particular subset of those resources.

Terminology Reasoning
~~~~~~~~~~~~~~~~~~~~~~~

Various terms other than project for this entity have been suggested. Here is the reasoning for (so far) staying with the term "project" over the following terms:

* **Team**
    A goal of the collaboration spaces design is to provide access control to common resources in a way that promotes safe collaboration.  The access control lists in such a space when applied to the use cases seem to more naturally represent a context around a specific set of resources rather than the people granted permissions. So 'team" was rejected because it just does not seem to work in practice and is too easily confused with groups.

* **Context**
    is close to the purpose of this entity, but in my opinion the term is too vague. It is quite naturally used when referring to a project as in "set your context to the Staging project in the Acme org." One suggestion has been to make the term more specific like "security context", "authorization context", or "collaboration context". "Security context" implies that the entity includes more security aspects than just ACLs and the others are just long.

* **Role-map** and **Environment**
    are good possible choices as well, but longer and more vague than project.

* **Space**
    is perhaps the closest to the intent of the "collaboration spaces" concept and so perhaps should be used instead of "projects.

I could fairly easily be convinced to use "space" or "context" if there is some consensus to change. For now, I'm leaving the current term as "project".

Specifying Access Controls to Resources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each ACL in a project specifies an optional role name, a set of users and groups, and a set of permissions bound to resources. Possible permissions are create, read, update, delete and are represented as a set of letters, e.g. all permissions would be "crud". Resources are specified in the flat resource namespace within the org. ACLs may reference resources through contain wild cards or reserved names, e.g. "services" to refer to all services in an org. For example, the ACL "Joe, c: services" specifies that Joe can create services. The ACL "Sue, d: services" specifies that Sue can delete any service, whereas the ACL "Sam, d:TestDB" indicates that Sam can only delete the service TestDB. There is an operational project in each org called "all" that initially contains a single row that gives the org creator all rights, e.g. "Sam, crud:\*"

Managing Delegation of Administration -- Rights to Grant Rights
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ACL list is a resource within a project that contains elements that can be further specified down to a specific permission by a path of the form acls/resource/user/permission. This allows the project ACLs to control access to itself to a very fine-grained level.
Some examples of ACLs in org Acme, project ProdApps:
* Joe, c:acls/apps -- Joe can grant permissions to all users regarding applications in this org.
* Sam, u:acls/Developers -- Sam can specify who can update membership of the Developers group whereas "Sam, u:Developers" would mean Sam could update the group membership but not delegate that permission to others.
* Sue, crud:acls/services/r -- Sue can give and remove permissions to anyone to read any or all services

Automatic ACLs
~~~~~~~~~~~~~~~

When a new resource is created, a new ACL is added to the creator's current project that gives them all rights to the resource and all rights to ACLs for the resource. For example, if user Joe creates an Auditors group, this ACL is added:

``Joe, crud:Auditors crud:acls/Auditors``

To make a group self maintaining, Joe could then add ``Auditors, u:Auditors``, meaning all members of the group Auditors can update the group.

Example Projects
~~~~~~~~~~~~~~~~~~

The examples below are intended to represent more of an end user's view of a project, so it does not include the full path of the resource in all cases. The subject of the ACL (the Users or Groups column) user and groups are listed without a path. The full path for the group Owners would be groups/Owners and the full path for user Joe would be something like ../../users/Joe, since users are outside of orgs, but for our purposes here they are listed without paths. Also, when ACLs are specified as a resource within a project, they should always be proceeded with path that include projects and their own project name, e.g. projects/Widgets/acls. For the samples below such paths will just start with acls.

An example project "Widgets" in the Acme Org:

=============== ==================  ==============================  =======================
Role Name       Users or Groups     Permissions to Resources        Description
=============== ==================  ==============================  =======================
Engineer        Joe                 | ru:WidgetShopApp,             Joe can read and update these 2 apps
                                    | ru:WidgetInventoryApp
DBA             db-developers       ru:WidgetsDB                    Members of the db-developers group can read and update this service
GroupAdmin      Sue                 | crud:groups,                  Sue can create, read, update, and delete groups, and she can delegate those permissions to others (i.e. create, read, delete, update acls on groups
                                    | crud:acls/groups
StagingAppAdmin Sam                 | ru:StagingApp,                Sam can update the StagingApp but cannot delete it, and he can give others permissions to update StagingApp
                                    | crud:acls/StagingApp/u
\               Tom                 | cd:apps,                      Tom can create and delete apps and services but he cannot give others those permissions.
                                    | cd:services
=============== ==================  ==============================  =======================

An example "all" project in the Acme Org:

=============== ==================  ==============================  =======================
Role Name       Users or Groups     Permissions to Resources        Description
=============== ==================  ==============================  =======================
OrgOwners       Joe, Owners         crud:projects                   Members of the Owners group and Joe can control permissions to any resource in the Org, including giving themselves permissions to modify other resources, but they would have to explicitly add those permissions.
Public          \*                  r:projects                      anyone can read all the project info and ACLs, and read group info and membership, but can't see into applications and services without other permissions
                                    r:groups
Monitors        SupportStaff        | r:apps,                       members of SupportStaff group can read all applications and services
                                    | r:services
SupportStaff    SupportStaff        u:SupportStaff,                 SupportStaff can update their own membership, and give that permission to others
                                    crud:acls/SupportStaff
=============== ==================  ==============================  =======================

Action Set
------------

This is the set of actions that a User can perform within an Org. In the current Cloud Foundry code, these are the commands that can be performed by VMC. There is an appendix to this document which maps current [VMC commands to required Permissions|https://wiki.springsource.com/display/ACDEV/VMC+Action+Set+with+Permissions]. If the implementation of action sets and permissions is not hard coded, but can be easily modified, the same Collaboration Spaces code could be used to provide access control to other layers of the overall CloudFoundry system such as BOSH.

Applying the Model
===================

Some scenarios for how the model would apply to specific situations.

Maintain simple initial user interaction on cloudfoundry.com
-------------------------------------------------------------

The current interaction of users with cloudfoundry.com should remain the same as it is now. To do this, when a user account is created, a corresponding org with its default "all" project giving that user all rights to the org. If a user targets a CloudFoundry instance as they do now, the default org is their personal org and the "all" project. With collaboration spaces they will be able to target a specific org other than their personal org, but that is optional. An upgrade from the current CloudFoundry user accounts to the collaboration spaces code should produce an org for each user, and an operational "all" project within that org. With appropriate defaults, users should see no change -- until they need it. Current users, passwords, apps, services, vmc can work as is.

Separate Monitoring from Application Development Team(s)
---------------------------------------------------------

Given an org Acme where Sam has all permissions in the "all" projects, Sam can create a group called Monitors. He can then add an ACL to "all" project like this:

``Monitors, r:services r:apps ru:Monitors`` -- members of the monitors group can read all services and apps and they can read and update their own group.

Sam can then create a project called ConsumerApps and add an ACL in the project such that user Joe has all rights to the acls in the project. Joe can then give himself permissions to create applications, services, groups, as well as add ACLs for users with any combination of permissions. The ACL in ConsumerApp would look like this:

``Joe, crud:apps crud:services crud:groups crud:acls``

Sam can then create another project called InternalApps with a similar structure and add an ACL giving Tom all permissions to the acls. The projects could share applications and resources or be completely disjoint. To share a resource, it would have to be added to a project by someone who had create permission to both the source and destination projects.

Sam could also create a project called JoesDemoApps and add Joe again with all permissions. At that point, Joe could create applications and services within the project.

When Joe is working on demo apps he can target just those apps with a command like::

            $ vmc target api.cloudfoundry.com Acme JoesDemoApps

When Joe is working on the ConsumerApps he can target just those apps like this::

            $ vmc target api.cloudfoundry.com Acme ConsumerApps


Whatever project Joe targets, he is isolated from permissions in the other project -- in other words, he cannot accidentally delete a consumer app while working in the demo apps. If Joe just targets the org, he should be set to the last project he had chosen, i.e. choosing a project within an org is sticky.

VMware applications within cloudfoundry.com
--------------------------------------------

There are a series of VMware applications that are intended to run on cloudfoundry.com: www, code, studio, the microcloud DNS service. These could be modeled similar to the projects described above for Sam and Acme. The org would be VMware and each set of applications could be developed and managed by its own team, and there could be a monitoring team to support overall application health.

Simple Integration with Horizon Application Manager
--------------------------------------------------------------------------

One of the policies that may be set on an org would be that it's users can come from a tenant within Horizon Application Manager.
Note: It still needs to be determined what protocol would be used. At the time of this writing, the Horizon team is developing an OAuth service and the OAuth2 and OpenID Connect specifications are expected to be final within a month or so. Current expectation is that OpenID Connect would build on the OAuth2 support and would be the preferred authentication protocol between a CFInstance and Horizon Application Manager. However, SAML is an option as well. Authentication tokens from Horizon should include group memberships. The CFInstance may be required to provision a user when receiving an authentication token (JIT provisioning), or it may be sufficient to control access with just group memberships, no user account required.

Simple Integration with Active Directory
------------------------------------------

One of the policies that may be set on an org would be that its users can come from an LDAP directory service such as Active Directory. In many ways this is similar to the "Simple Integration with Horizon" use case -- including JIT provisioning and group membership -- but the CFInstance pulls the authentication and group information from directory service with LDAP rather than having it pushed into the CFInstance and authentication time via SAML or OpenIDConnect.

Easy Onboarding of New Users
------------------------------

We should be able to add people to a group with an email address that will send them an invitation. Basically creates a partial user account, when the user accepts the invitation or logs in, the account is completed. Users with the partial account can still be added to Projects.

Setting Context and Separation of duties
------------------------------------------

For any native application such as vmc, a User needs to set a target to the CFInstance they want to interact with. If they only set the target to a CFInstance such as api.cloudfoundry.com, they default to their own personal org and have all permissions to resources within that org. If a User targets a CFInstance, an org, and project, they are restricted to the permissions granted them within that project. A scenario that uses separation of duties based on projects is described in the "Separate Monitoring from Application Development Team(s)" section above.

Moving Applications and Services between Orgs
-------------------------------------------------

As we migrate from the current single user application structure on cloudfoundry.com to the collaboration spaces system we will need the ability to move sets of applications and resources between orgs. It is possible that this capability is not just a migration path, but will also be required in future CFInstances with collaboration spaces. Since applications and services can be interrelated, we will need to be able to move them as a group. Therefore, there should be a MoveResources action that takes a source list of resources in an org and a destination org. The user performing the action must have delete permissions in the source org and create permissions in the destination org. All resources in the list are moved as a unit. If the system determines that the resources are not a self-contained set -- i.e. there are dependencies on other resources not included in the list -- the action fails.

Open Issues
=============

What to do about proxy permissions?
-------------------------------------

We still need to determine how an Org or CFInstance admin can perform operations on behalf of a user.

Do we need physical separation of identity systems per layer?
---------------------------------------------------------------

Multiple instantiations of the collaboration systems code should happen at various layers in a CFInstance. For example, in Bento the BOSH layer should have a physically separate system from the layer containing the cloud controller.

How do permissions for BOSH and other layers map to this model?
-----------------------------------------------------------------

The BOSH layer has different actions and possibly different permission sets from the vcap layer. This has not been mapped out yet.

What can we learn from other systems?
--------------------------------------

Current research to learn from other systems has included AWS IAM, github, pivotal, GAE, general LDAP-style, x.500, etc. Some notes from these systems are in a sub-page: [Other Collaboration Spaces Models|https://wiki.springsource.com/display/ACDEV/Other+Collaboration+Spaces+Models]. Gerrit needs to be added to the sub-page. What other systems should be included?

What is the relation of custom domain names and Orgs?
-------------------------------------------------------

Need to understand DNS and routing interaction with applications and Services. Initial suggestion is that DNS names are another resource like applications and services which are owned by an org.

Should Resources be visible from other Orgs?
----------------------------------------------

This has been suggested, but I have not added it yet until I understand some use cases.

Extensibility to service specific actions
-------------------------------------------

A service may have specific actions that the Cloud Controller does not know anything about. We should be able to package up the org/project/group information into a token for the service. 

