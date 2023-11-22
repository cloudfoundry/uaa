package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Test;

public class UserConfigTest {

    @Test
    public void testDefaultConfig() {
        UserConfig userConfig = new UserConfig();
        assertTrue(userConfig.getDefaultGroups().contains("openid"));
        assertTrue(userConfig.getAllowedGroups() == null);       // all groups allowed
        assertTrue(userConfig.resultingAllowedGroups() == null); // all groups allowed
    }

    @Test
    public void testResultingAllowedGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(List.of("openid"));
        userConfig.setAllowedGroups(List.of("uaa.user"));
        assertTrue(userConfig.getDefaultGroups().equals(List.of("openid")));
        assertTrue(userConfig.getAllowedGroups().equals(List.of("uaa.user")));
        assertTrue(userConfig.resultingAllowedGroups().equals(Set.of("openid", "uaa.user")));
    }

    @Test
    public void testNoDefaultGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(null);
        userConfig.setAllowedGroups(List.of("uaa.user"));
        assertTrue(userConfig.getDefaultGroups() == null);
        assertTrue(userConfig.getAllowedGroups().equals(List.of("uaa.user")));
        assertTrue(userConfig.resultingAllowedGroups().equals(Set.of("uaa.user")));
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
