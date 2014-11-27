package org.cloudfoundry.identity.uaa.zone;

public interface IdentityProviderProvisioning {

    public IdentityProvider create(IdentityProvider identityProvider);

    public IdentityProvider retrieve(String id);
    
    public IdentityProvider retrieveByOrigin(String origin);
    
    
}
