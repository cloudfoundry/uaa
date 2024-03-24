package org.cloudfoundry.identity.uaa.oauth.exceptions;

import org.springframework.security.authentication.InsufficientAuthenticationException;

public class UnapprovedClientAuthenticationException extends InsufficientAuthenticationException {

  public UnapprovedClientAuthenticationException(String msg) {
    super(msg);
  }

  public UnapprovedClientAuthenticationException(String msg, Throwable t) {
    super(msg, t);
  }
}
