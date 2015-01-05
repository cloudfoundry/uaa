package org.cloudfoundry.identity.uaa.zone;

import java.util.List;

public interface IdentityZoneProvisioning {

    public IdentityZone create(IdentityZone identityZone);

    public IdentityZone retrieve(String id);
    
    public IdentityZone retrieveBySubdomain(String subdomain);

    List<IdentityZone> retrieveAll();
    
    
}
