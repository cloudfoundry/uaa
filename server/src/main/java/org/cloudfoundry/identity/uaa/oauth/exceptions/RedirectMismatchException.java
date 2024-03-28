package org.cloudfoundry.identity.uaa.oauth.exceptions;

public class RedirectMismatchException extends ClientAuthenticationException {

  public RedirectMismatchException(String msg, Throwable t) {
    super(msg, t);
  }

  public RedirectMismatchException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "invalid_grant";
  }
}
