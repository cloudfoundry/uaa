package org.cloudfoundry.identity.uaa.mfa;

import org.junit.Test;

import static junit.framework.Assert.assertNull;

public class GoogleMfaProviderConfigTest {

    GoogleMfaProviderConfig config;

    @Test
    public void testDefaultConfig() {
        config = new GoogleMfaProviderConfig();
        assertNull(config.getProviderDescription());
        assertNull(config.getIssuer());
    }
}