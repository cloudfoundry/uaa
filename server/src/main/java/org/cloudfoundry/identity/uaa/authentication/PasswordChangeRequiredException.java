package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.InteractionRequiredException;

public class PasswordChangeRequiredException extends InteractionRequiredException {

  private final UaaAuthentication authentication;

  public PasswordChangeRequiredException(UaaAuthentication authentication, String msg) {
    super(msg);
    this.authentication = authentication;
  }

  public UaaAuthentication getAuthentication() {
    return authentication;
  }
}
