package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class UserConfigTest {

  @Test
  public void getMaxUsers() {
    UserConfig userConfig = new UserConfig();
    assertNull(userConfig.getMaxUsers());
  }

  @Test
  public void setMaxUsers() {
    UserConfig userConfig = new UserConfig();
    userConfig.setMaxUsers(100);
    assertEquals(Integer.valueOf(100), userConfig.getMaxUsers());
  }
}
