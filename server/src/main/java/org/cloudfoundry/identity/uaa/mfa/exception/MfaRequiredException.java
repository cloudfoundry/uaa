package org.cloudfoundry.identity.uaa.mfa.exception;

import org.cloudfoundry.identity.uaa.oauth.InteractionRequiredException;

public class MfaRequiredException extends InteractionRequiredException {

  public MfaRequiredException(String msg) {
    super(msg);
  }
}
