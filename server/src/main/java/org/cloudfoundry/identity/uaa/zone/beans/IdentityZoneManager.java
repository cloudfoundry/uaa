package org.cloudfoundry.identity.uaa.zone.beans;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;

public interface IdentityZoneManager {
    IdentityZone getCurrentIdentityZone();

    String getCurrentIdentityZoneId();

    boolean isCurrentZoneUaa();

    void setCurrentIdentityZone(final IdentityZone mockIdentityZone);
}
