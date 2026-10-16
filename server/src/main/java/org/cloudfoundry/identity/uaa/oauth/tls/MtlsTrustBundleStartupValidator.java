package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Startup check of the default zone's trust bundles. Not implemented yet: checks nothing. */
@Component
public class MtlsTrustBundleStartupValidator implements SmartInitializingSingleton {

    public MtlsTrustBundleStartupValidator(@Value("${uaa.mtls.enabled:false}") boolean deploymentEnabled,
            IdentityZoneProvisioning zones) {
    }

    @Override
    public void afterSingletonsInstantiated() {
    }
}
