package org.cloudfoundry.identity.uaa.security;

import com.beust.jcommander.internal.Sets;
import org.apache.commons.io.IOUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Objects;

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

        return nothingElseChanged && !disableInternalUserManagement && !Objects.equals(scimUserFromDb.getName(), scimUserFromRequest.getName());
    }
}
