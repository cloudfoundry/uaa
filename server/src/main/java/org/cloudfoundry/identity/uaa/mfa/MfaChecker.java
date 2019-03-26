package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;

public class MfaChecker {

    private final IdentityZoneProvisioning identityZoneProvisioning;

    public MfaChecker(IdentityZoneProvisioning identityZoneProvisioning) {
        this.identityZoneProvisioning = identityZoneProvisioning;
    }

    public boolean isMfaEnabled(IdentityZone zone) {
        return zone.getConfig().getMfaConfig().isEnabled();
    }

    public boolean isMfaEnabledForZoneId(String zoneId) {
        return isMfaEnabled(identityZoneProvisioning.retrieve(zoneId));
    }

    public boolean isRequired(IdentityZone zone, String originKey) {
        return zone.getConfig().getMfaConfig().getIdentityProviders().contains(originKey);
    }
}
