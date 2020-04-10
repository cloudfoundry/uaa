package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

public class TokenRevokedException extends InvalidTokenException {

  public TokenRevokedException(String msg) {
    super(msg);
  }

  public TokenRevokedException(String msg, Throwable t) {
    super(msg, t);
  }
}
