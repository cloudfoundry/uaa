package org.cloudfoundry.identity.uaa.zone;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

@Component
public class DenyAccessToUaaAdvice {

    public void checkIdentityZone(IdentityZone identityZone) {
        if (identityZone != null && IdentityZone.getUaaZoneId().equalsIgnoreCase(identityZone.getId())) {
            throw new AccessDeniedException("Access to UAA is not allowed.");
        }
    }

    public void checkIdentityZoneId(String identityZoneId) {
        if (IdentityZone.getUaaZoneId().equalsIgnoreCase(identityZoneId)) {
            throw new AccessDeniedException("Access to UAA is not allowed.");
        }
    }

}
