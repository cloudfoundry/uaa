package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

/**
 * Unchecked exception to signal that a user has an invalid field, e.g. username.
 *
 * @author Dave Syer
 */
public class InvalidScimResourceException extends ScimException {

  /** @param message a message for the caller */
  public InvalidScimResourceException(String message) {
    super(message, HttpStatus.BAD_REQUEST);
  }
}
