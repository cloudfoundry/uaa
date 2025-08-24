package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.CREATE;
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
