package org.cloudfoundry.identity.uaa.zone;

import java.util.Set;

public class UserConfigValidator {

    // add a private constructor to hide the implicit public one
    private UserConfigValidator() {
    }

    public static void validate(UserConfig config) throws InvalidIdentityZoneConfigurationException {
        if (config == null) {
            return;
        }

        Set<String> allowedGroups = config.resultingAllowedGroups();
        if (allowedGroups != null && allowedGroups.isEmpty()) {
            String message = "At least one group must be allowed";
            throw new InvalidIdentityZoneConfigurationException(message);
        }

        int maxUsers = config.getMaxUsers();
        if (maxUsers < -1 || maxUsers == 0 || maxUsers > Integer.MAX_VALUE) {
            throw new InvalidIdentityZoneConfigurationException("Maximum numbers of users in the zone in invalid, allowed numbers are between 1 and 2147483647");
        }
    }
}
