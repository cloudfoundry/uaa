package org.cloudfoundry.identity.uaa.oauth;

public class InvalidSignatureException extends RuntimeException {
  public InvalidSignatureException(String message) {
    super(message);
  }

  public InvalidSignatureException(String message, Exception exception) {
    super(message, exception);
  }
}
