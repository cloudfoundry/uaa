package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationEvent;

public abstract class AuthEvent extends ApplicationEvent {

  private boolean userModified = true;

  public AuthEvent(UaaUser user, boolean userUpdated) {
    super(user);
    this.userModified = userUpdated;
  }

  public UaaUser getUser() {
    return (UaaUser) source;
  }

  public boolean isUserModified() {
    return userModified;
  }
}
