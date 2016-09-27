package org.cloudfoundry.identity.uaa.account;

public class UserAccountStatus {
  public Boolean isLocked() {
    return locked;
  }

  public void setLocked(Boolean locked) {
    this.locked = locked;
  }

  private Boolean locked;
}
