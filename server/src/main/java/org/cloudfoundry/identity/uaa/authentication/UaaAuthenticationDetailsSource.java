package org.cloudfoundry.identity.uaa.authentication;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;

/** @author Luke Taylor */
public class UaaAuthenticationDetailsSource
    implements AuthenticationDetailsSource<HttpServletRequest, UaaAuthenticationDetails> {

  @Override
  public UaaAuthenticationDetails buildDetails(HttpServletRequest context) {
    return new UaaAuthenticationDetails(context);
  }
}
