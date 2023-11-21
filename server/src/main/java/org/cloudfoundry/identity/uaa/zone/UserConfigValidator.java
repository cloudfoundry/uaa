package org.cloudfoundry.identity.uaa.zone;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserConfigValidator {
    private static Logger logger = LoggerFactory.getLogger(UserConfigValidator.class);

    // add a private constructor to hide the implicit public one
    private UserConfigValidator() {
    }

    public static void validate(UserConfig config) throws InvalidIdentityZoneConfigurationException {
        Set<String> allowedGroups = (config == null) ? null : config.resultingAllowedGroups();
        if ((allowedGroups != null) && (allowedGroups.isEmpty())) {
            String message = "At least one group must be allowed";
            logger.error(message);
            throw new InvalidIdentityZoneConfigurationException(message);
        }
    }
}
