package org.cloudfoundry.identity.uaa.provider;

import java.util.List;

public interface IdentityProviderProvisioning {

  IdentityProvider create(IdentityProvider identityProvider, String zoneId);

  IdentityProvider update(IdentityProvider identityProvider, String zoneId);

  IdentityProvider retrieve(String id, String zoneId);

  List<IdentityProvider> retrieveActive(String zoneId);

  List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId);

  IdentityProvider retrieveByOrigin(String origin, String zoneId);

  default IdentityProvider retrieveByOriginIgnoreActiveFlag(String origin, String zoneId) {
    return retrieveByOrigin(origin, zoneId);
  }
}
