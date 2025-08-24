package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;


class UserConfigValidatorTest {

    @Test
    void defaultConfig() throws InvalidIdentityZoneConfigurationException {
        UserConfigValidator.validate(new UserConfig()); // defaultGroups not empty, allowedGroups is null
    }

    @Test
    void nullConfig() throws InvalidIdentityZoneConfigurationException {
        UserConfigValidator.validate(null);
    }

    @Test
    void allowedGroupsEmpty() throws InvalidIdentityZoneConfigurationException {
        UserConfig userConfig = new UserConfig();
        userConfig.setAllowedGroups(Collections.emptyList());
        UserConfigValidator.validate(userConfig);
    }

    @Test
    void noGroupsAllowed() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(Collections.emptyList());
        userConfig.setAllowedGroups(Collections.emptyList());
        assertThatExceptionOfType(InvalidIdentityZoneConfigurationException.class).isThrownBy(() -> // no groups allowed
                UserConfigValidator.validate(userConfig));
    }

    @Test
    void noUsersAllowed() {
        UserConfig userConfig = new UserConfig();
        userConfig.setMaxUsers(0);
        assertThatExceptionOfType(InvalidIdentityZoneConfigurationException.class).isThrownBy(() ->
                UserConfigValidator.validate(userConfig));
    }
}