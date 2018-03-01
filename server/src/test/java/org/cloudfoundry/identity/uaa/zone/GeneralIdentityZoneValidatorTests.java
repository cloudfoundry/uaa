package org.cloudfoundry.identity.uaa.zone;


import org.junit.Test;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.CREATE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.DELETE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneValidator.Mode.MODIFY;
import static org.mockito.Mockito.*;

public class GeneralIdentityZoneValidatorTests {


    GeneralIdentityZoneConfigurationValidator zoneConfigurationValidator = mock(GeneralIdentityZoneConfigurationValidator.class);
    GeneralIdentityZoneValidator validator = new GeneralIdentityZoneValidator(zoneConfigurationValidator);

    @Test
    public void validate_right_mode() throws InvalidIdentityZoneDetailsException, InvalidIdentityZoneConfigurationException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        for (IdentityZoneValidator.Mode  mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            reset(zoneConfigurationValidator);
            when(zoneConfigurationValidator.validate(any(), any())).thenReturn(config);
            validator.validate(zone, mode);
            verify(zoneConfigurationValidator, times(1)).validate(same(zone), same(mode));
        }
    }
}
