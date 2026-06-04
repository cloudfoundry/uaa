package org.cloudfoundry.identity.uaa.zone;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;


class UserConfigValidatorTest {

    @Test
    void defaultConfig() throws Exception {
        UserConfigValidator.validate(new UserConfig()); // defaultGroups not empty, allowedGroups is null
    }

    @Test
    void nullConfig() throws Exception {
        UserConfigValidator.validate(null);
    }

    @Test
    void allowedGroupsEmpty() throws Exception {
        UserConfig userConfig = new UserConfig();
        userConfig.setAllowedGroups(Collections.emptyList());
        UserConfigValidator.validate(userConfig);
    }

    @Test
    void noGroupsAllowed() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(Collections.emptyList());
        userConfig.setAllowedGroups(Collections.emptyList());
        assertThatThrownBy(() -> // no groups allowed
                UserConfigValidator.validate(userConfig)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidIdentityZoneConfigurationException.class));
    }

    @Test
    void noUsersAllowed() {
        UserConfig userConfig = new UserConfig();
        userConfig.setMaxUsers(0);
        assertThatThrownBy(() ->
                UserConfigValidator.validate(userConfig)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidIdentityZoneConfigurationException.class));
    }
}