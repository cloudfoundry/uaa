package org.cloudfoundry.identity.uaa.mfa_provider;

import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;

public class GoogleMfaProviderConfigTest {

    GoogleMfaProviderConfig config;

    @Test
    public void testDefaultConfig() {
        config = new GoogleMfaProviderConfig();
        assertEquals(6, config.getDigits());
        assertEquals(30, config.getDuration());
        assertEquals(GoogleMfaProviderConfig.Algorithm.SHA256, config.getAlgorithm());
        assertNull(config.getProviderDescription());
        assertNull(config.getIssuer());
    }
}