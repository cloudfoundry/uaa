package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class IdpAlreadyExistsException extends UaaException {

  public IdpAlreadyExistsException(String msg) {
    super("idp_exists", msg, 409);
  }
}
