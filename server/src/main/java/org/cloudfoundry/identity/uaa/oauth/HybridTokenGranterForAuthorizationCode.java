package org.cloudfoundry.identity.uaa.oauth;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;

import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.util.Assert;

public class HybridTokenGranterForAuthorizationCode extends AbstractTokenGranter {

  public HybridTokenGranterForAuthorizationCode(
      AuthorizationServerTokenServices tokenServices,
      MultitenantClientServices clientDetailsService,
      OAuth2RequestFactory requestFactory) {
    super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE_AUTHORIZATION_CODE);
  }

  @Override
  protected OAuth2Authentication getOAuth2Authentication(
      ClientDetails client, TokenRequest clientToken) {

    Authentication userAuth = SecurityContextHolder.getContext().getAuthentication();
    if (userAuth == null || !userAuth.isAuthenticated()) {
      throw new InsufficientAuthenticationException("There is no currently logged in user");
    }
    Assert.state(
        clientToken instanceof ImplicitTokenRequest,
        "An ImplicitTokenRequest is required here. Caller needs to wrap the TokenRequest.");

    OAuth2Request requestForStorage = ((ImplicitTokenRequest) clientToken).getOAuth2Request();

    return new OAuth2Authentication(requestForStorage, userAuth);
  }
}
