package org.cloudfoundry.identity.uaa.security;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import java.util.Objects;

public class ScimUserSelfUpdateAllowed {
    private ScimUserProvisioning scimUserProvisioning;

    public ScimUserSelfUpdateAllowed(ScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }

    public boolean isAllowed(String userId, ScimUser scimUserFromRequest, boolean internalUserManagementDisabled) {
        String zoneId = IdentityZoneHolder.get().getId();
        ScimUser scimUserFromDb;

        try {
            scimUserFromDb = scimUserProvisioning.retrieve(userId, zoneId);
        } catch (ScimResourceNotFoundException e) {
            return true;
        }

        boolean nothingElseChanged = scimUserFromDb.getPrimaryEmail().equals(scimUserFromRequest.getPrimaryEmail()) &&
                Objects.equals(scimUserFromDb.getSalt(), scimUserFromRequest.getSalt()) &&
                (Objects.equals(scimUserFromDb.getExternalId(), scimUserFromRequest.getExternalId()) || scimUserFromDb.getExternalId() == null && scimUserFromRequest.getExternalId().isEmpty()) &&
                Objects.equals(scimUserFromDb.getDisplayName(), scimUserFromRequest.getDisplayName()) &&
                Objects.equals(scimUserFromDb.getPhoneNumbers(), scimUserFromRequest.getPhoneNumbers()) &&
                scimUserFromDb.getEmails().containsAll(scimUserFromRequest.getEmails()) &&
                scimUserFromDb.getUserName().equals(scimUserFromRequest.getUserName()) &&
                scimUserFromDb.isVerified() == scimUserFromRequest.isVerified() &&
                scimUserFromDb.isActive() == (scimUserFromRequest.isActive()) &&
                scimUserFromDb.getOrigin().equals(scimUserFromRequest.getOrigin());

        return nothingElseChanged && !internalUserManagementDisabled && !Objects.equals(scimUserFromDb.getName(), scimUserFromRequest.getName());
    }
}
