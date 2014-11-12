package org.cloudfoundry.identity.uaa.zone;

public interface IdentityZoneProvisioning {

    public IdentityZone create(IdentityZone identityZone);

    public IdentityZone retrieve(String id);
}
