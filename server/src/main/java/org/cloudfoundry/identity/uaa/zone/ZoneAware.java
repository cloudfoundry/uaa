package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManager;

public interface ZoneAware {
    default IdentityZone retrieveZone() {
        return IdentityZoneHolder.get();
    }

    default SamlKeyManager retrieveKeyManager() {
        return IdentityZoneHolder.getSamlKeyManager();
    }
}
