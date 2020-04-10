package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class InvalidCodeException extends UaaException {

  public InvalidCodeException(String error, String description, int status) {
    super(error, description, status);
  }
}
