package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserAccountStatus {

  private Boolean locked;

  private Boolean passwordChangeRequired;

  public Boolean getLocked() {
    return locked;
  }

  public void setLocked(Boolean locked) {
    this.locked = locked;
  }

  public Boolean isPasswordChangeRequired() {
    return passwordChangeRequired;
  }

  public void setPasswordChangeRequired(Boolean passwordChangeRequired) {
    this.passwordChangeRequired = passwordChangeRequired;
  }
}
