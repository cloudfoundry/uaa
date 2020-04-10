package org.cloudfoundry.identity.uaa.mfa.exception;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class MfaAlreadyExistsException extends UaaException {

  public MfaAlreadyExistsException(String msg) {
    super("mfa_exists", msg, 409);
  }
}
