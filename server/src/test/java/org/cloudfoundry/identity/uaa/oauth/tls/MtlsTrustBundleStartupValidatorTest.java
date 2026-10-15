package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Startup checks only the default zone's own bundle definitions. Client references are not checked
 * at startup: token-time resolution denies a client whose reference does not resolve.
 */
class MtlsTrustBundleStartupValidatorTest {
    private static final Map<String, String> INVALID_BUNDLES = Map.of("broken", "not a certificate");
    private IdentityZoneProvisioning zones;

    @BeforeEach
    void setUp() {
        zones = mock(IdentityZoneProvisioning.class);
    }

    @Test
    void invalidDefaultZoneBundleDefinitionPreventsStartup() {
        givenDefaultZone(true, INVALID_BUNDLES);

        assertThatThrownBy(() -> validator(true).afterSingletonsInstantiated())
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("broken");
    }

    @Test
    void neverLooksUpOtherZones() {
        givenDefaultZone(true, Map.of());

        validator(true).afterSingletonsInstantiated();

        verify(zones).retrieve(IdentityZone.getUaaZoneId());
        verify(zones, never()).retrieveAll();
    }

    @Test
    void deploymentSwitchOffSkipsValidation() {
        givenDefaultZone(true, INVALID_BUNDLES);

        assertThatCode(() -> validator(false).afterSingletonsInstantiated()).doesNotThrowAnyException();
        verifyNoInteractions(zones);
    }

    @Test
    void defaultZoneDisabledSkipsValidation() {
        givenDefaultZone(false, INVALID_BUNDLES);

        assertThatCode(() -> validator(true).afterSingletonsInstantiated()).doesNotThrowAnyException();
    }

    private void givenDefaultZone(boolean mtlsEnabled, Map<String, String> bundles) {
        IdentityZone zone = IdentityZone.getUaa();
        zone.getConfig().getMtls().setEnabled(mtlsEnabled);
        zone.getConfig().getMtls().setTrustBundles(bundles);
        when(zones.retrieve(IdentityZone.getUaaZoneId())).thenReturn(zone);
    }

    private MtlsTrustBundleStartupValidator validator(boolean deploymentEnabled) {
        return new MtlsTrustBundleStartupValidator(deploymentEnabled, zones);
    }
}
