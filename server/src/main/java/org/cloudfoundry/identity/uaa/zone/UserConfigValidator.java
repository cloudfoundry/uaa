package org.cloudfoundry.identity.uaa.zone;

import java.util.Set;

public final class UserConfigValidator {

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

        long maxUsers = config.getMaxUsers();
        if (maxUsers < -1 || maxUsers == 0) {
            throw new InvalidIdentityZoneConfigurationException("Maximum number of users in the zone is invalid, either use -1 or a value more than 0.");
        }
    }
}
