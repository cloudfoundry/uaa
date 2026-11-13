package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import static org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter.DEFAULT_ZONE_SUBDOMAIN_PATH;

@Component("identityZoneValidator")
public class GeneralIdentityZoneValidator implements IdentityZoneValidator {
    private static final int MAX_SUBDOMAIN_LENGTH = 255;
    private final IdentityZoneConfigurationValidator configValidator;

    public GeneralIdentityZoneValidator(final IdentityZoneConfigurationValidator configValidator) {
        this.configValidator = configValidator;
    }

    @Override
    public IdentityZone validate(IdentityZone identityZone, Mode mode) throws InvalidIdentityZoneDetailsException {
        if (IdentityZoneHolder.getUaaZone().getId().equalsIgnoreCase(identityZone.getId()) && !identityZone.isActive()) {
            throw new InvalidIdentityZoneDetailsException("The default zone cannot be set inactive.", null);
        }
        if (DEFAULT_ZONE_SUBDOMAIN_PATH.equalsIgnoreCase(identityZone.getSubdomain())) {
            throw new InvalidIdentityZoneDetailsException(
                    "The subdomain '" + DEFAULT_ZONE_SUBDOMAIN_PATH + "' is reserved and cannot be used.", null);
        }
        String subdomain = identityZone.getSubdomain();
        boolean isDefaultZone = IdentityZone.getUaaZoneId().equalsIgnoreCase(identityZone.getId());
        if (mode != Mode.DELETE && subdomain != null && subdomain.length() > MAX_SUBDOMAIN_LENGTH) {
            throw new InvalidIdentityZoneDetailsException(
                    "The subdomain must not exceed " + MAX_SUBDOMAIN_LENGTH + " characters.", null);
        }
        // Keep legacy zones deletable, and allow the default zone's empty subdomain.
        if (mode != Mode.DELETE && !(isDefaultZone && "".equals(subdomain)) &&
                (subdomain == null || !UaaUrlUtils.isValidSubdomain(subdomain))) {
            throw new InvalidIdentityZoneDetailsException(
                    "The subdomain must contain only ASCII letters, digits, or hyphens, " +
                            "and must start and end with a letter or digit.", null);
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
