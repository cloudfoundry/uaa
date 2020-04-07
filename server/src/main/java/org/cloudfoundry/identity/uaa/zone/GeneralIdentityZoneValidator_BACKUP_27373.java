package org.cloudfoundry.identity.uaa.zone;

<<<<<<< HEAD
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
=======
import org.springframework.stereotype.Component;
>>>>>>> 6a1fa12cdae22697bf84939fc6d041561529b4a1
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

        // allow default identity zone to have empty subdomain
        if (!(identityZone.isUaa() || UaaUrlUtils.isValidSubdomain(identityZone.getSubdomain()))) {
            throw new InvalidIdentityZoneDetailsException("The subdomain is invalid: " + identityZone.getSubdomain(), null);
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
