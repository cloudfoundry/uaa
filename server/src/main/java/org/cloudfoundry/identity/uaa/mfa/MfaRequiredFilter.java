package org.cloudfoundry.identity.uaa.mfa;

import java.io.IOException;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.mfa.exception.MfaRequiredException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

public class MfaRequiredFilter extends GenericFilterBean {

  private static Logger logger = LoggerFactory.getLogger(MfaRequiredFilter.class);

  private final MfaChecker checker;
  private final AuthenticationEntryPoint entryPoint;

  public MfaRequiredFilter(MfaChecker checker, AuthenticationEntryPoint entryPoint) {
    this.checker = checker;
    this.entryPoint = entryPoint;
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;
    if (isMfaRequiredAndMissing()) {
      logger.debug("MFA is configured, but missing in authentication. Invoking entry point");
      entryPoint.commence(
          request, response, new MfaRequiredException("Multi-factor authentication required."));
    } else {
      chain.doFilter(request, response);
    }
  }

  protected boolean isMfaRequiredAndMissing() {
    Authentication a = SecurityContextHolder.getContext().getAuthentication();
    if (a == null || a instanceof AnonymousAuthenticationToken) {
      return false;
    }
    if (!(a instanceof UaaAuthentication)) {
      return false;
    }
    UaaAuthentication uaaAuth = (UaaAuthentication) a;
    if (!mfaRequired()) {
      return false;
    }

    Set<String> methods = uaaAuth.getAuthenticationMethods();
    return methods == null || !methods.contains("mfa");
  }

  protected boolean mfaRequired() {
    return checker.isMfaEnabled(IdentityZoneHolder.get());
  }
}
