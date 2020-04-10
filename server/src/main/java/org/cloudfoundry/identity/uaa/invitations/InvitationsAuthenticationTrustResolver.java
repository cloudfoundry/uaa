package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

public class InvitationsAuthenticationTrustResolver implements AuthenticationTrustResolver {

  private AuthenticationTrustResolver delegate = new AuthenticationTrustResolverImpl();

  @Override
  public boolean isAnonymous(Authentication authentication) {
    if (authentication != null
        && authentication.getAuthorities() != null
        && authentication.getAuthorities().contains(UaaAuthority.UAA_INVITED)) {
      return false;
    } else {
      return delegate.isAnonymous(authentication);
    }
  }

  @Override
  public boolean isRememberMe(Authentication authentication) {
    return delegate.isRememberMe(authentication);
  }
}
