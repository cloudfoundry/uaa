package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Evaluates both switches against the current request's zone, without caching tenant state. */
@Component
public class MtlsFeaturePolicy {
    private final boolean deploymentEnabled;
    private final IdentityZoneManager identityZoneManager;

    public MtlsFeaturePolicy(@Value("${uaa.mtls.enabled:false}") boolean deploymentEnabled,
            IdentityZoneManager identityZoneManager) {
        this.deploymentEnabled = deploymentEnabled;
        this.identityZoneManager = identityZoneManager;
    }

    public boolean isEnabled() {
        return isEnabled(deploymentEnabled, identityZoneManager.getCurrentIdentityZone());
    }

    public static boolean isEnabled(boolean deploymentEnabled, IdentityZone zone) {
        return deploymentEnabled && zone.getConfig().getMtls() != null && zone.getConfig().getMtls().isEnabled();
    }
}
