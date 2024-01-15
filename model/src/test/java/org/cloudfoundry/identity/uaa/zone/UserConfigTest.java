package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Test;

public class UserConfigTest {

    @Test
    public void testDefaultConfig() {
        UserConfig userConfig = new UserConfig();
        assertTrue(userConfig.getDefaultGroups().contains("openid"));
        assertNull(userConfig.getAllowedGroups());       // all groups allowed
        assertNull(userConfig.resultingAllowedGroups()); // all groups allowed
    }

    @Test
    public void testResultingAllowedGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(List.of("openid"));
        userConfig.setAllowedGroups(List.of("uaa.user"));
        assertEquals(List.of("openid"), userConfig.getDefaultGroups());
        assertEquals(List.of("uaa.user"), userConfig.getAllowedGroups());
        assertEquals(Set.of("openid", "uaa.user"), userConfig.resultingAllowedGroups());
    }

    @Test
    public void testNoDefaultGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(null);
        userConfig.setAllowedGroups(List.of("uaa.user"));
        assertNull(userConfig.getDefaultGroups());
        assertEquals(List.of("uaa.user"), userConfig.getAllowedGroups());
        assertEquals(Set.of("uaa.user"), userConfig.resultingAllowedGroups());
    }

    @Test
    public void testNoDefaultAndNoAllowedGroups() {
        UserConfig userConfig = new UserConfig();
        userConfig.setDefaultGroups(null);
        userConfig.setAllowedGroups(null);
        assertNull(userConfig.getDefaultGroups());
        assertNull(userConfig.getAllowedGroups());       // all groups allowed
        assertNull(userConfig.resultingAllowedGroups()); // all groups allowed
    }
    @Test
    public void getMaxUsers() {
      UserConfig userConfig = new UserConfig();
      assertEquals(-1, userConfig.getMaxUsers());
    }

    @Test
    public void setMaxUsers() {
      UserConfig userConfig = new UserConfig();
      userConfig.setMaxUsers(100);
      assertEquals(100, userConfig.getMaxUsers());
    }
}
