package org.cloudfoundry.identity.uaa.extensions;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Makes the current zone the default zone with {@code config.mtls.enabled=true}. Zones opt in to
 * mTLS, so tests exercising mTLS behaviour must enable it explicitly; a test can still install its
 * own zone with {@link IdentityZoneHolder#set(IdentityZone)}.
 */
public class MtlsEnabledZoneExtension implements BeforeEachCallback, AfterEachCallback {

    public static IdentityZone mtlsEnabledUaaZone() {
        IdentityZone zone = IdentityZone.getUaa();
        zone.getConfig().getMtls().setEnabled(true);
        return zone;
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        IdentityZoneHolder.set(mtlsEnabledUaaZone());
    }

    @Override
    public void afterEach(ExtensionContext context) {
        IdentityZoneHolder.clear();
    }
}
