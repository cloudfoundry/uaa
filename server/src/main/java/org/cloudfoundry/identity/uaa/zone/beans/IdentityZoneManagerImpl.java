package org.cloudfoundry.identity.uaa.zone.beans;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.stereotype.Component;

@Component("identityZoneManager")
public class IdentityZoneManagerImpl implements IdentityZoneManager {
    @Override
    public IdentityZone getCurrentIdentityZone() {
        return IdentityZoneHolder.get();
    }

    @Override
    public String getCurrentIdentityZoneId() {
        return IdentityZoneHolder.getCurrentZoneId();
    }

    @Override
    public boolean isCurrentZoneUaa() {
        return IdentityZoneHolder.isUaa();
    }

    @Override
    public void setCurrentIdentityZone(final IdentityZone identityZone) {
        IdentityZoneHolder.set(identityZone);
    }
}
