package org.cloudfoundry.identity.uaa.invitations;

import lombok.Data;
import org.cloudfoundry.identity.uaa.scim.ScimUser;

@Data
public class AcceptedInvitation {
    private final String redirectUri;
    private final ScimUser user;
}
