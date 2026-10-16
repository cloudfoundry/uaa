package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Checks the default zone's mTLS trust-bundle definitions after the zone bootstrap has finished.
 *
 * <p>Only the default zone is inspected, and only when mTLS is enabled for both the deployment and
 * that zone: installations can have tens of thousands of zones, so startup must not scale with the
 * tenant count. Tenant bundle definitions are validated on every zone update. Client references to
 * bundles are not checked here, because that would require reading every client of the zone; a
 * reference that does not resolve is denied at token time.
 */
@Component
public class MtlsTrustBundleStartupValidator implements SmartInitializingSingleton {
    private final boolean deploymentEnabled;
    private final IdentityZoneProvisioning zones;

    public MtlsTrustBundleStartupValidator(@Value("${uaa.mtls.enabled:false}") boolean deploymentEnabled,
            IdentityZoneProvisioning zones) {
        this.deploymentEnabled = deploymentEnabled;
        this.zones = zones;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (!deploymentEnabled) {
            return;
        }
        IdentityZone defaultZone = zones.retrieve(IdentityZone.getUaaZoneId());
        if (MtlsFeaturePolicy.isEnabled(true, defaultZone)) {
            MtlsTrustBundles.validate(defaultZone.getConfig().getMtls().getTrustBundles());
        }
    }
}
