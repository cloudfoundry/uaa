package org.cloudfoundry.identity.uaa.oauth.exceptions;

public class UserDeniedAuthorizationException extends OAuth2Exception {

  public UserDeniedAuthorizationException(String msg, Throwable t) {
    super(msg, t);
  }

  public UserDeniedAuthorizationException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "access_denied";
  }

}
