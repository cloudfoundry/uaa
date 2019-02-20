package org.cloudfoundry.identity.uaa.zone.beans;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.stereotype.Component;

@Component
public class IdentityZoneManagerImpl implements IdentityZoneManager {
    @Override
    public String getCurrentIdentityZoneId() {
        return IdentityZoneHolder.get().getId();
    }
}
