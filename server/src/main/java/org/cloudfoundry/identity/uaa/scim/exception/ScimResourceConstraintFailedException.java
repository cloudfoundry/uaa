package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

/**
 * Unchecked exception signalling that a user account was not in the state expected (e.g. non-unique
 * username).
 *
 * @author Dave Syer
 */
public class ScimResourceConstraintFailedException extends ScimException {

  /** @param message a message for the caller */
  public ScimResourceConstraintFailedException(String message) {
    super(message, HttpStatus.PRECONDITION_FAILED);
  }
}
