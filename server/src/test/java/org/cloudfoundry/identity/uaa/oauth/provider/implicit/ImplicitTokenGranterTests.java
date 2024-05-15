package org.cloudfoundry.identity.uaa.oauth.provider.implicit;

import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class ImplicitTokenGranterTests {

  private ImplicitTokenGranter implicitTokenGranter;
  private AuthorizationServerTokenServices tokenServices;
  private ClientDetailsService clientDetailsService;
  private OAuth2RequestFactory requestFactory;
  private TokenRequest tokenRequest;
  private OAuth2Request oauth2Request;
  private ImplicitTokenRequest implicitTokenRequest;

  @Before
  public void setUp() {
    tokenServices = mock(AuthorizationServerTokenServices.class);
    clientDetailsService = mock(ClientDetailsService.class);
    requestFactory = mock(OAuth2RequestFactory.class);
    tokenRequest = mock(TokenRequest.class);
    oauth2Request = mock(OAuth2Request.class);
    implicitTokenGranter = new ImplicitTokenGranter(tokenServices, clientDetailsService, requestFactory);
    implicitTokenRequest = new ImplicitTokenRequest(tokenRequest, oauth2Request);
  }

  @After
  public void cleanup() {
    SecurityContextHolder.clearContext();
  }

  @Test
  public void getOAuth2Authentication() {
    Authentication authentication = mock(Authentication.class);
    when(authentication.isAuthenticated()).thenReturn(true);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    implicitTokenGranter.getOAuth2Authentication(mock(ClientDetails.class), implicitTokenRequest);
  }

  @Test(expected = InsufficientAuthenticationException.class)
  public void getOAuth2AuthenticationException() {
    Authentication authentication = mock(Authentication.class);
    when(authentication.isAuthenticated()).thenReturn(false);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    implicitTokenGranter.getOAuth2Authentication(mock(ClientDetails.class), implicitTokenRequest);
  }

  @Test
  public void setImplicitGrantService() {
    implicitTokenGranter.setImplicitGrantService(null);
  }
}