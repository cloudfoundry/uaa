package org.cloudfoundry.identity.uaa.zone;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class UserConfigTest {

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
