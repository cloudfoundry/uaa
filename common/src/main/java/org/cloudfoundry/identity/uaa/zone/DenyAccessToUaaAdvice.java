package org.cloudfoundry.identity.uaa.zone;

import org.springframework.security.access.AccessDeniedException;

public class DenyAccessToUaaAdvice {
    
    public void checkIdentityZone(IdentityZone identityZone) {
        if (IdentityZone.getUaa().equals(identityZone)) {
            throw new AccessDeniedException("Access to UAA is not allowed.");
        }
    }
    
    public void checkIdentityZoneId(String identityZoneId) {
        if (IdentityZone.getUaa().getId().equals(identityZoneId)) {
            throw new AccessDeniedException("Access to UAA is not allowed.");
        }
    }

}
