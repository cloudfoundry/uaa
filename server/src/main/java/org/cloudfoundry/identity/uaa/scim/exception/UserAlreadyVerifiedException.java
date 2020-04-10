package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

public class UserAlreadyVerifiedException extends ScimException {

  public static final String DESC = "This user has already been verified.";

  public UserAlreadyVerifiedException() {
    super(DESC, HttpStatus.METHOD_NOT_ALLOWED);
  }
}
