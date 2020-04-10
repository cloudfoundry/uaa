package org.cloudfoundry.identity.uaa.zone;

import java.util.List;

public interface IdentityZoneProvisioning {

  IdentityZone create(IdentityZone identityZone);

  IdentityZone update(IdentityZone identityZone);

  IdentityZone retrieve(String id);

  IdentityZone retrieveBySubdomain(String subdomain);

  List<IdentityZone> retrieveAll();

  default IdentityZone retrieveIgnoreActiveFlag(String id) {
    return retrieve(id);
  }
}
