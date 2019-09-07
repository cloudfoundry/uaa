package org.cloudfoundry.identity.uaa.zone;


import org.junit.Test;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.CREATE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.DELETE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.MODIFY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

public class GeneralIdentityZoneValidatorTests {


    GeneralIdentityZoneConfigurationValidator zoneConfigurationValidator = mock(GeneralIdentityZoneConfigurationValidator.class);
    GeneralIdentityZoneValidator validator = new GeneralIdentityZoneValidator(zoneConfigurationValidator);

    @Test
    public void validate_right_mode() throws InvalidIdentityZoneDetailsException, InvalidIdentityZoneConfigurationException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        checkValidationForModes(zone, config);
    }

    @Test
    public void uaa_zone_inactive_fails() {
        IdentityZone uaaZone = IdentityZoneHolder.getUaaZone();
        uaaZone.setActive(false);
        for (IdentityZoneValidator.Mode mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            try {
                validator.validate(uaaZone, mode);
                fail();
            } catch (InvalidIdentityZoneDetailsException e) {
                assertEquals("The default zone cannot be set inactive.", e.getMessage());
            }
        }
    }

    @Test
    public void other_zone_inactive_succeeds() throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        zone.setActive(false);
        checkValidationForModes(zone, config);
    }

    private void checkValidationForModes(IdentityZone zone, IdentityZoneConfiguration config) throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        for (IdentityZoneValidator.Mode  mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            reset(zoneConfigurationValidator);
            when(zoneConfigurationValidator.validate(any(), any())).thenReturn(config);
            validator.validate(zone, mode);
            verify(zoneConfigurationValidator, times(1)).validate(same(zone), same(mode));
        }
    }
}
