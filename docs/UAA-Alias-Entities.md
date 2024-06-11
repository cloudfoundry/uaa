# UAA Alias Entities (Experimental)

This guide describes the motivation behind the alias feature of UAA as well as its usage.

## Motivation

The alias feature addresses the goal of using one single UAA installation for several tenants and isolating them from 
each other.

At first glance, UAA already supports a concept for tenant isolation: identity zones.
All entities managed by UAA, i.e. OAuth clients, identity providers, users, groups, etc., are associated with an 
identity zone and operations on them are limited to the context of the current identity zone.

However, components like CF runtime are not making use of the identity zone concept and are only aware of the "uaa" 
zone.
CF runtime does not support performing OAuth flows against any other zone than "uaa".
This implies that users that are only present in a custom identity zone cannot log in there.

One option to solve this issue would be to enable specifying the identity zone during authorization flows against custom
zones, similar to specifying the origin key of the IdP to use for authentication.
However, this entails the two following problems.
First, all components relying on UAA as an authorization server would require adjustments to specify the identity zone 
to use when initiating authorization flows.
Second, all OAuth clients used for these authorization flows, which currently are only present in the "uaa" zone, would 
need to be duplicated to the custom zones that need to use them or might use them in the future.

The alias concept addresses this issue by supporting isolated management of users and their IdPs in custom identity 
zones while guaranteeing that components relying on authentication to the "uaa" identity zone still work.
This is done by managing synchronized copies of users and identity providers in both the "uaa" and the custom zone.
The copy of such an entity will be referred to as its "alias".
An entity and its alias reference each other by the newly introduced properties `alias_id` (ID of the alias) and 
`alias_zid` (zone ID of the alias).

In practice, administrators of the tenants will receive access to their custom identity zone, where they can manage IdPs
and users in an isolated way.
These users must have an alias to the "uaa" zone, respectively.
Any changes the administrator performs on users or identity providers in the custom zone will be propagated to the 
aliases in the "uaa" zone.
At runtime, the components relying on UAA as an authorization server will use the alias of the users in the "uaa" zone 
and therefore do not require any adjustments.

### Example: Cloud Controller

An example for a component that relies on UAA as an authorization server is the CF Cloud Controller.
Among other functionalities, it manages the roles of users on org and space level.
This is done by internally assigning the roles to the user IDs they receive from UAA.

For example, when logging in via the `cf login` command, a token is fetched from UAA in the context of the "uaa" zone.
The cloud controller APIs are then called with this token, from which it can read the user's ID.
However, if the user would be moved to a custom zone without using an alias, the login against UAA would not work, since
the user is not present in the "uaa" zone.

When using the alias feature, the administrator will only have access to his/her IdZ, but create all users as well as 
their identity providers with an alias to the "uaa" zone.
Since these users are now also present in the "uaa" zone (as aliases of the ones in the custom zone), they can fetch 
tokens from UAA (e.g., during `cf login`) and call the Cloud Controller APIs with them. 

## Constraints

- aliases can only be created from or to the `uaa` zone
- the zone referenced in `alias_zid` must exist
- an identity provider can only have an alias if it is of type OIDC, SAML or OAuth 2.0
- a user can only have an alias if the identity provider to which the user belongs has an alias to the **same** zone
  - this is not required the other way around: an IdP with alias does not require its users to also have an alias

## API

Creating a new alias and updating or deleting entities together with their existing alias is done by setting the 
properties `alias_id` and `alias_zid` in the existing endpoints for identity providers and users. 

### Create a new alias

An alias can be created either directly during creation of the entity or during the update of an existing entity.

In the create or update request, the property `alias_zid` must be set to the desired zone where the alias shall be 
maintained.
The field `alias_id` must be left empty.
In the response, it will contain the ID of the alias entity created in the zone referenced by `alias_zid`.

### Update an entity with alias

Whenever an entity with alias is updated, the changes to the entity are propagated to the alias entity.
In the body of the update requests, the properties `alias_id` and `alias_zid` must be left unchanged.

The only exceptions are the three timestamp properties of users, i.e., `password_last_modified`, `last_logon_time` and 
`previous_logon_time`.
For them, the entity and its alias will have their own values, respectively.

### Delete an entity with alias

If an entity with alias is deleted, the alias is also deleted.

In the case of IdPs, all users of the alias IdP (regardless of whether they have an alias themselves or not) are also 
deleted. 

## Deletion of an identity zone

When deleting an identity zone that contains entities with alias, all those identity providers that have an alias to the
deleted zone are also deleted.

> **WARNING:** Please note that the users of this IdP in the alias zone are not deleted.
> They will still have a reference (via `alias_zid` and `alias_id`) to their deleted counterparts in the deleted zone.

## Enablement

The alias entities feature can be enabled or disabled by setting `login.aliasEntitiesEnabled` to `true` or `false`.
If the flag is disabled, no new alias can be created and entities with an existing alias cannot be updated or deleted.
In both cases, a response with status code `422 Unprocessable Entity` is returned. 

Please note that disabling the flag does not lead to existing entities with alias being removed.

In addition to enabling the alias feature, one must ensure that no groups can be created that would give users inside a 
custom zone any authorizations in other zones (e.g., `zones.<zone ID>.admin`).
This can be achieved by using the allow list for groups (`userConfig.allowedGroups`) in the configuration of the 
identity zone. 











