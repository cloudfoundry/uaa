package org.cloudfoundry.identity.uaa.account;

public class UserAccountStatus {
  public boolean isLocked() {
    return locked;
  }

  public void setLocked(boolean locked) {
    this.locked = locked;
  }

  private boolean locked;
}
