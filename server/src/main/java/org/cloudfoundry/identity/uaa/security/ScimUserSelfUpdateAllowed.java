package org.cloudfoundry.identity.uaa.security;

import org.apache.commons.io.IOUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class ScimUserSelfUpdateAllowed {

    public static final int USER_ID_PATH_PARAMETER_INDEX = 1;
    private ScimUserProvisioning scimUserProvisioning;

    public ScimUserSelfUpdateAllowed(ScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }

    public boolean isAllowed(HttpServletRequest request, boolean disableInternalUserManagement) throws IOException {
        String requestBody = IOUtils.toString(request.getReader());
        ScimUser scimUserFromRequest = JsonUtils.readValue(requestBody, ScimUser.class);

        String id = UaaUrlUtils.extractPathVariableFromUrl(USER_ID_PATH_PARAMETER_INDEX, UaaUrlUtils.getRequestPath(request));
        String zoneId = IdentityZoneHolder.get().getId();
        ScimUser scimUserFromDb;

        try {
            scimUserFromDb = scimUserProvisioning.retrieve(id, zoneId);
        } catch (ScimResourceNotFoundException e) {
            return true;
        }

        if (!scimUserFromDb.getPrimaryEmail().equals(scimUserFromRequest.getPrimaryEmail())) {
            return false;
        }

        if (!scimUserFromDb.getSalt().equals(scimUserFromRequest.getSalt())) {
            return false;
        }

        if (!scimUserFromDb.getExternalId().equals(scimUserFromRequest.getExternalId())) {
            return false;
        }

        if (!scimUserFromDb.getDisplayName().equals(scimUserFromRequest.getDisplayName())) {
            return false;
        }

        if (!scimUserFromDb.getPhoneNumbers().containsAll(scimUserFromRequest.getPhoneNumbers())) {
            return false;
        }

        if (!scimUserFromDb.getEmails().containsAll(scimUserFromRequest.getEmails())) {
            return false;
        }

        if (!scimUserFromDb.getUserName().equals(scimUserFromRequest.getUserName())) {
            return false;
        }

        if (scimUserFromDb.isVerified() != scimUserFromRequest.isVerified()) {
            return false;
        }

        if (scimUserFromDb.isActive() != (scimUserFromRequest.isActive())) {
            return false;
        }

        if (!scimUserFromDb.getOrigin().equals(scimUserFromRequest.getOrigin())) {
            return false;
        }

        if (disableInternalUserManagement) {
            return scimUserFromDb.getName().equals(scimUserFromRequest.getName());

        }

        return true;
    }

}
