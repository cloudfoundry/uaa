package org.cloudfoundry.identity.uaa.zone;


import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.CREATE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.DELETE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.MODIFY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

public class GeneralIdentityZoneValidatorTests {


    GeneralIdentityZoneConfigurationValidator zoneConfigurationValidator = mock(GeneralIdentityZoneConfigurationValidator.class);
    GeneralIdentityZoneValidator validator = new GeneralIdentityZoneValidator(zoneConfigurationValidator);
    List<IdentityZoneValidator.Mode> modes = Arrays.asList(CREATE, MODIFY, DELETE);

    @Test
    public void validate_right_mode() throws InvalidIdentityZoneDetailsException, InvalidIdentityZoneConfigurationException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        checkValidationForModes(zone, config);
    }

    @Test
    public void uaa_zone_inactive_fails() throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException{
        IdentityZone uaaZone = IdentityZoneHolder.getUaaZone();
        uaaZone.setActive(false);
        for (IdentityZoneValidator.Mode mode : modes) {
            checkValidationForModes(uaaZone, uaaZone.getConfig(), true, "The default zone cannot be set inactive.");
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

    @Test
    public void uaa_zone_succeeds() throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        IdentityZone uaaZone = IdentityZoneHolder.getUaaZone();
        checkValidationForModes(uaaZone, uaaZone.getConfig());
    }

    @Test
    public void empty_subdomain_not_uaa_fails() throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "");
        for (IdentityZoneValidator.Mode mode : modes) {
            checkValidationForModes(zone, zone.getConfig(), true, "The subdomain is invalid: ");
        }
    }

    @Test
    public void valid_subdomain_succeeds() throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "test");
        checkValidationForModes(zone, zone.getConfig());
    }

    @Test
    public void invalid_subdomain_fails() throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "test_test");
        for (IdentityZoneValidator.Mode mode : modes) {
            checkValidationForModes(zone, zone.getConfig(), true, "The subdomain is invalid: test_test");
        }
    }

    private void checkValidationForModes(IdentityZone zone, IdentityZoneConfiguration config)
            throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        checkValidationForModes(zone, config, false, null);
    }

    private void checkValidationForModes(IdentityZone zone, IdentityZoneConfiguration config, boolean fails,
            String message)
            throws InvalidIdentityZoneConfigurationException, InvalidIdentityZoneDetailsException {
        for (IdentityZoneValidator.Mode mode : modes) {
            reset(zoneConfigurationValidator);
            when(zoneConfigurationValidator.validate(any(), any())).thenReturn(config);
            if (fails) {
                try {
                    validator.validate(zone, mode);
                    fail();
                } catch (InvalidIdentityZoneDetailsException e) {
                    assertEquals(message, e.getMessage());
                }
            } else {
                validator.validate(zone, mode);
                verify(zoneConfigurationValidator, times(1)).validate(same(zone), same(mode));
            }
        }
    }
}
