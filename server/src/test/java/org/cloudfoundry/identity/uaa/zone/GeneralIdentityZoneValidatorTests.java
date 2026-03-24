package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.CREATE;
import static org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter.DEFAULT_ZONE_SUBDOMAIN_PATH;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.DELETE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.MODIFY;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class GeneralIdentityZoneValidatorTests {

    @Mock
    GeneralIdentityZoneConfigurationValidator zoneConfigurationValidator;

    @InjectMocks
    GeneralIdentityZoneValidator validator;

    @Test
    void validateRightMode() throws InvalidIdentityZoneDetailsException, InvalidIdentityZoneConfigurationException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        checkValidationForModes(zone, config);
    }

    @Test
    void uaaZoneInactiveFails() {
        IdentityZone uaaZone = IdentityZoneHolder.getUaaZone();
        uaaZone.setActive(false);
        for (IdentityZoneValidator.Mode mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            try {
                validator.validate(uaaZone, mode);
                fail("");
            } catch (InvalidIdentityZoneDetailsException e) {
                assertThat(e.getMessage()).isEqualTo("The default zone cannot be set inactive.");
            }
        }
    }

    @Test
    void reservedSubdomainDefault_rejectsForAllModes() {
        for (String subdomain : List.of(DEFAULT_ZONE_SUBDOMAIN_PATH,
                DEFAULT_ZONE_SUBDOMAIN_PATH.substring(0, 1).toUpperCase() + DEFAULT_ZONE_SUBDOMAIN_PATH.substring(1),
                DEFAULT_ZONE_SUBDOMAIN_PATH.toUpperCase())) {
            IdentityZone zone = MultitenancyFixture.identityZone("id", subdomain);
            for (IdentityZoneValidator.Mode mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
                try {
                    validator.validate(zone, mode);
                    fail("Expected InvalidIdentityZoneDetailsException for subdomain: " + subdomain + " mode: " + mode);
                } catch (InvalidIdentityZoneDetailsException e) {
                    assertThat(e.getMessage()).contains("reserved");
                }
            }
        }
    }

    @Test
    void otherZoneInactiveSucceeds() throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        zone.setActive(false);
        checkValidationForModes(zone, config);
    }

    private void checkValidationForModes(IdentityZone zone, IdentityZoneConfiguration config) throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        for (IdentityZoneValidator.Mode mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            reset(zoneConfigurationValidator);
            when(zoneConfigurationValidator.validate(any(), any())).thenReturn(config);
            validator.validate(zone, mode);
            verify(zoneConfigurationValidator, times(1)).validate(same(zone), same(mode));
        }
    }
}
