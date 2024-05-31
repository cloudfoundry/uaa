package org.cloudfoundry.identity.uaa.oauth;

public class InvalidSignatureHashException extends InvalidSignatureException {

  private static final long serialVersionUID = 5458857726949999613L;

  public InvalidSignatureHashException(String message) {
    super(message);
  }

  public InvalidSignatureHashException(String message, Throwable cause) {
    super(message, cause);
  }
}
