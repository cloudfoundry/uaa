package org.cloudfoundry.identity.uaa.zone.beans;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;

public interface IdentityZoneManager {

  IdentityZone getCurrentIdentityZone();

  void setCurrentIdentityZone(final IdentityZone mockIdentityZone);

  String getCurrentIdentityZoneId();

  boolean isCurrentZoneUaa();
}
