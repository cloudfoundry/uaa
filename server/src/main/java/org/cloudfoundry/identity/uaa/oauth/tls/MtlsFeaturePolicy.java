package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Deployment and zone mTLS switches. Not implemented yet: mTLS is never enabled. */
@Component
public class MtlsFeaturePolicy {

    public MtlsFeaturePolicy(@Value("${uaa.mtls.enabled:false}") boolean deploymentEnabled,
            IdentityZoneManager identityZoneManager) {
    }

    public boolean isEnabled() {
        return false;
    }

    public static boolean isEnabled(boolean deploymentEnabled, IdentityZone zone) {
        return false;
    }
}
