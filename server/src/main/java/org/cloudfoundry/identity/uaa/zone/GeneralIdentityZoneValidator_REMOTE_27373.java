package org.cloudfoundry.identity.uaa.zone;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component("identityZoneValidator")
public class GeneralIdentityZoneValidator implements IdentityZoneValidator {
    private final IdentityZoneConfigurationValidator configValidator;

    public GeneralIdentityZoneValidator(final IdentityZoneConfigurationValidator configValidator) {
        this.configValidator = configValidator;
    }

    @Override
    public IdentityZone validate(IdentityZone identityZone, Mode mode) throws InvalidIdentityZoneDetailsException {
        if (IdentityZoneHolder.getUaaZone().getId().equals(identityZone.getId()) && !identityZone.isActive()) {
            throw new InvalidIdentityZoneDetailsException("The default zone cannot be set inactive.", null);
        }
        try {
            identityZone.setConfig(configValidator.validate(identityZone, mode));
        } catch (InvalidIdentityZoneConfigurationException ex) {
            String configErrorMessage = StringUtils.hasText(ex.getMessage()) ? ex.getMessage() : "";
            throw new InvalidIdentityZoneDetailsException("The zone configuration is invalid. " + configErrorMessage, ex);
        }
        return identityZone;
    }
}
