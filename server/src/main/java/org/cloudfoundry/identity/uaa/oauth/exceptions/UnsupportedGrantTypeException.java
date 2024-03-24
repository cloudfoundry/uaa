package org.cloudfoundry.identity.uaa.oauth.exceptions;

public class UnsupportedGrantTypeException extends OAuth2Exception {

  public UnsupportedGrantTypeException(String msg, Throwable t) {
    super(msg, t);
  }

  public UnsupportedGrantTypeException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "unsupported_grant_type";
  }
}