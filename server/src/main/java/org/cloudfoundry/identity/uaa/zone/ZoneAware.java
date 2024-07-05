package org.cloudfoundry.identity.uaa.zone;

public interface ZoneAware {
    default IdentityZone retrieveZone() {
        return IdentityZoneHolder.get();
    }
}
