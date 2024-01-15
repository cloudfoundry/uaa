package org.cloudfoundry.identity.uaa.zone;

import org.junit.Test;

import java.util.Collections;


public class UserConfigValidatorTest {

    @Test
    public void testDefaultConfig() throws InvalidIdentityZoneConfigurationException {
        UserConfigValidator.validate(new UserConfig()); // defaultGroups not empty, allowedGroups is null
    }

    @Test
    public void testNullConfig() throws InvalidIdentityZoneConfigurationException {
        UserConfigValidator.validate(null);
    }

    @Test
    public void testAllowedGroupsEmpty() throws InvalidIdentityZoneConfigurationException {
        UserConfig userConfig = new UserConfig();
        userConfig.setAllowedGroups(Collections.emptyList());
        UserConfigValidator.validate(userConfig);
    }

    @Test(expected = InvalidIdentityZoneConfigurationException.class)
    public void testNoGroupsAllowed() throws InvalidIdentityZoneConfigurationException {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(Collections.emptyList());
        userConfig.setAllowedGroups(Collections.emptyList()); // no groups allowed
        UserConfigValidator.validate(userConfig);
    }

    @Test(expected = InvalidIdentityZoneConfigurationException.class)
    public void testNoUsersAllowed() throws InvalidIdentityZoneConfigurationException {
        UserConfig userConfig = new UserConfig();
        userConfig.setMaxUsers(0);
        UserConfigValidator.validate(userConfig);
    }
}