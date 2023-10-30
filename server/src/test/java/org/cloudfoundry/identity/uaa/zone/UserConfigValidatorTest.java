package org.cloudfoundry.identity.uaa.zone;

import org.junit.Test;

import java.util.Collections;
import java.util.List;


public class UserConfigValidatorTest {

    @Test
    public void testDefaultConfig() throws InvalidIdentityZoneConfigurationException {
        UserConfigValidator.validate(new UserConfig());
    }

    @Test
    public void testNullConfig() throws InvalidIdentityZoneConfigurationException {
        UserConfigValidator.validate(null);
    }

    @Test(expected = InvalidIdentityZoneConfigurationException.class)
    public void testAllowedGroupsEmpty() throws InvalidIdentityZoneConfigurationException {
        UserConfig userConfig = new UserConfig();
        userConfig.setAllowedGroups(Collections.emptyList());
        UserConfigValidator.validate(userConfig);
    }

    @Test(expected = InvalidIdentityZoneConfigurationException.class)
    public void testDefaultGroupsNotAllowed() throws InvalidIdentityZoneConfigurationException {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(List.of("openid","uaa.user"));
        userConfig.setAllowedGroups(List.of("uaa.user")); // openid not allowed
        UserConfigValidator.validate(userConfig);
    }
}