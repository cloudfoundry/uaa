package org.cloudfoundry.identity.uaa.security;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import java.util.Objects;

public class ScimUserUpdateDiff {
    private final ScimUserProvisioning scimUserProvisioning;

    public ScimUserUpdateDiff(ScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }

    public boolean isAnythingOtherThanNameDifferent(String userId, ScimUser scimUserFromRequest) {
        String zoneId = IdentityZoneHolder.get().getId();
        ScimUser scimUserFromDb;

        try {
            scimUserFromDb = scimUserProvisioning.retrieve(userId, zoneId);
        } catch (ScimResourceNotFoundException e) {
            return true;
        }

        return isInternalUser(scimUserFromDb) &&
                scimUserFromDb.getPrimaryEmail().equals(scimUserFromRequest.getPrimaryEmail()) &&
                Objects.equals(scimUserFromDb.getSalt(), scimUserFromRequest.getSalt()) &&
                Objects.equals(scimUserFromDb.getDisplayName(), scimUserFromRequest.getDisplayName()) &&
                externalIdsEquivalent(scimUserFromRequest, scimUserFromDb) &&
                phoneNumbersEquivalent(scimUserFromRequest, scimUserFromDb) &&
                originsEquivalent(scimUserFromRequest, scimUserFromDb) &&
                scimUserFromDb.getUserName().equals(scimUserFromRequest.getUserName()) &&
                scimUserFromDb.isVerified() == scimUserFromRequest.isVerified() &&
                scimUserFromDb.isActive() == (scimUserFromRequest.isActive());
    }

    private boolean originsEquivalent(ScimUser scimUserFromRequest, ScimUser scimUserFromDb) {
        return scimUserFromDb.getOrigin().equals(scimUserFromRequest.getOrigin()) ||
                (scimUserFromDb.getOrigin().equals(OriginKeys.UAA) && UaaStringUtils.isNullOrEmpty(scimUserFromRequest.getOrigin()));
    }

    private boolean phoneNumbersEquivalent(ScimUser scimUserFromRequest, ScimUser scimUserFromDb) {
        Object firstPhoneNumberFromDb = scimUserFromDb.getPhoneNumbers() == null ? null : (scimUserFromDb.getPhoneNumbers().isEmpty() ? null : scimUserFromDb.getPhoneNumbers().getFirst());
        Object firstPhoneNumberFromRequest = scimUserFromRequest.getPhoneNumbers() == null ? null : (scimUserFromRequest.getPhoneNumbers().isEmpty() ? null : scimUserFromRequest.getPhoneNumbers().getFirst());
        return Objects.equals(firstPhoneNumberFromDb, firstPhoneNumberFromRequest);
    }

    private boolean externalIdsEquivalent(ScimUser scimUserFromRequest, ScimUser scimUserFromDb) {
        return Objects.equals(scimUserFromDb.getExternalId(), scimUserFromRequest.getExternalId()) ||
                scimUserFromDb.getExternalId() == null && scimUserFromRequest.getExternalId().isEmpty();
    }

    private boolean isInternalUser(ScimUser scimUserFromDb) {
        return scimUserFromDb.getOrigin().equals(OriginKeys.UAA);
    }
}
