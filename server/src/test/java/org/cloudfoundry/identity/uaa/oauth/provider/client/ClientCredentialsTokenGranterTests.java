package org.cloudfoundry.identity.uaa.oauth.provider.client;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ClientCredentialsTokenGranterTests {

  private AuthorizationServerTokenServices tokenServices;
  private ClientCredentialsTokenGranter clientCredentialsTokenGranter;
  private ClientDetailsService clientDetailsService;
  private OAuth2RequestFactory requestFactory;
  private TokenRequest tokenRequest;

  @Before
  public void setUp() throws Exception {
    tokenServices = mock(AuthorizationServerTokenServices.class);
    clientDetailsService = mock(ClientDetailsService.class);
    requestFactory = mock(OAuth2RequestFactory.class);
    tokenRequest = mock(TokenRequest.class);
    clientCredentialsTokenGranter = new ClientCredentialsTokenGranter(tokenServices, clientDetailsService, requestFactory);
  }

  @Test
  public void grant() {
    OAuth2Request oAuth2Request = mock(OAuth2Request.class);
    when(clientDetailsService.loadClientByClientId(any())).thenReturn(mock(ClientDetails.class));
    when(requestFactory.createOAuth2Request(any(), any())).thenReturn(oAuth2Request);
    when(tokenServices.createAccessToken(any())).thenReturn(mock(OAuth2AccessToken.class));
    when(oAuth2Request.getAuthorities()).thenReturn(Collections.EMPTY_LIST);
    assertNotNull(clientCredentialsTokenGranter.grant(TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS, tokenRequest));
  }

  @Test
  public void grantNoToken() {
    OAuth2Request oAuth2Request = mock(OAuth2Request.class);
    when(clientDetailsService.loadClientByClientId(any())).thenReturn(mock(ClientDetails.class));
    when(requestFactory.createOAuth2Request(any(), any())).thenReturn(oAuth2Request);
    when(tokenServices.createAccessToken(any())).thenReturn(null);
    when(oAuth2Request.getAuthorities()).thenReturn(Collections.EMPTY_LIST);
    assertNull(clientCredentialsTokenGranter.grant(TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS, tokenRequest));
  }
}