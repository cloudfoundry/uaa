package org.cloudfoundry.identity.uaa.zone;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserConfigValidator {
    private static Logger logger = LoggerFactory.getLogger(UserConfigValidator.class);

    public static void validate(UserConfig config) throws InvalidIdentityZoneConfigurationException {
        List<String> defaultGroups = (config == null) ? null : config.getDefaultGroups();
        List<String> allowedGroups = (config == null) ? null : config.getAllowedGroups();
        if (allowedGroups != null) {
            if (allowedGroups.isEmpty()) {
                String message = "At least one group must be allowed";
                logger.error(message);
                throw new InvalidIdentityZoneConfigurationException(message);
            }
            if ((defaultGroups == null) || (!allowedGroups.containsAll(defaultGroups))) {
                String message = "All default groups must be allowed";
                logger.error(message);
                throw new InvalidIdentityZoneConfigurationException(message);
            }
        }
    }
}
