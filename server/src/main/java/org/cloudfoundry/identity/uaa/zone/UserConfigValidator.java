package org.cloudfoundry.identity.uaa.zone;

import java.util.Set;

public class UserConfigValidator {

    // add a private constructor to hide the implicit public one
    private UserConfigValidator() {
    }

    public static void validate(UserConfig config) throws InvalidIdentityZoneConfigurationException {
        Set<String> allowedGroups = (config == null) ? null : config.resultingAllowedGroups();
        if ((allowedGroups != null) && (allowedGroups.isEmpty())) {
            String message = "At least one group must be allowed";
            throw new InvalidIdentityZoneConfigurationException(message);
        }
    }
}
