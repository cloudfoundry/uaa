External group membership auditing
==================================

During external authentication, UAA reconciles the user's stored external
group memberships with the authorities supplied by the identity provider.
When this reconciliation successfully removes a stale membership, UAA
publishes a GroupModifiedEvent for that group.

The event contains the group's ID, display name, identity zone, and member
IDs remaining after the removal, including an empty list if the last member
was removed. Memberships that remain unchanged, removals that fail, and
memberships already removed by another request do not produce this event.

This applies to the shared external group reconciliation used by OAuth/OIDC,
SAML, and LDAP authentication. It does not change which memberships UAA
removes or grants.
