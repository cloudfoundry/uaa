package org.cloudfoundry.identity.uaa.oauth;

public class InvalidSignatureException extends RuntimeException {

  private static final long serialVersionUID = 5458857726945157613L;

  private InvalidSignatureException() {
  }

  public InvalidSignatureException(String message) {
    super(message);
  }

  public InvalidSignatureException(String message, Throwable cause) {
    super(message, cause);
  }
}
