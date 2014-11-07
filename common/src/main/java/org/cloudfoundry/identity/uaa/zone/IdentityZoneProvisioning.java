package org.cloudfoundry.identity.uaa.zone;

public interface IdentityZoneProvisioning {

    public IdentityZone createZone(IdentityZone identityZone);

    public IdentityZone retrieve(String id);
}
