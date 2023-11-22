package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

public class UserConfigTest {

    @Test
    public void testDefaultConfig() {
        UserConfig userConfig = new UserConfig();
        assertTrue(userConfig.getDefaultGroups() != null);
        assertTrue(userConfig.getDefaultGroups().contains("uaa.user"));
        assertTrue(userConfig.getAllowedGroups() == null);       // all groups allowed
        assertTrue(userConfig.resultingAllowedGroups() == null); // all groups allowed
    }

    @Test
    public void testNoDefaultGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(null);
        userConfig.setAllowedGroups(List.of("uaa.user"));
        assertTrue(userConfig.getDefaultGroups() == null);
        assertTrue(userConfig.getAllowedGroups() != null);
        assertTrue(userConfig.getAllowedGroups().contains("uaa.user"));
        assertTrue(userConfig.resultingAllowedGroups() != null);
        assertTrue(userConfig.resultingAllowedGroups().contains("uaa.user"));
    }

    @Test
    public void testNoDefaultAndNoAllowedGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(null);
        userConfig.setAllowedGroups(null);
        assertTrue(userConfig.getDefaultGroups() == null);
        assertTrue(userConfig.getAllowedGroups() == null);       // all groups allowed
        assertTrue(userConfig.resultingAllowedGroups() == null); // all groups allowed
    }
}
