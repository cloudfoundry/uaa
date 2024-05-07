package org.cloudfoundry.identity.uaa.oauth.provider.request;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.security.beans.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class DefaultOAuth2RequestFactoryTests {

  private DefaultOAuth2RequestFactory defaultOAuth2RequestFactory;
  private ClientDetailsService clientDetailsService;
  private ClientDetails clientDetails;
  private Map<String, String> requestParameters;

  @Before
  public void setUp() throws Exception {
    clientDetails = mock(ClientDetails.class);
    clientDetailsService = mock(ClientDetailsService.class);
    when(clientDetailsService.loadClientByClientId(any())).thenReturn(clientDetails);
    defaultOAuth2RequestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
    requestParameters = Map.of("client_id", "id");
  }

  @Test
  public void setSecurityContextAccessor() {
    defaultOAuth2RequestFactory.setSecurityContextAccessor(new DefaultSecurityContextAccessor());
    assertNotNull(defaultOAuth2RequestFactory);
  }

  @Test
  public void setCheckUserScopes() {
    defaultOAuth2RequestFactory.setCheckUserScopes(true);
    assertNotNull(defaultOAuth2RequestFactory);
  }

  @Test
  public void createAuthorizationRequest() {
    assertNotNull(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters));
  }

  @Test
  public void createOAuth2Request() {
    assertNotNull(defaultOAuth2RequestFactory.createOAuth2Request(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters)));
  }

  @Test
  public void createTokenRequest() {
    assertNotNull(defaultOAuth2RequestFactory.createTokenRequest(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters), ""));
  }

  @Test
  public void testCreateTokenRequest() {
    when(clientDetails.getClientId()).thenReturn("id");
    assertNotNull(defaultOAuth2RequestFactory.createTokenRequest(requestParameters, clientDetails));
  }

  @Test(expected = InvalidClientException.class)
  public void testCreateTokenRequestDifferentClientId() {
    when(clientDetails.getClientId()).thenReturn("my-client-id");
    defaultOAuth2RequestFactory.createTokenRequest(requestParameters, clientDetails);
  }

  @Test
  public void testCreateOAuth2Request() {
    when(clientDetails.getClientId()).thenReturn("id");
    assertNotNull(defaultOAuth2RequestFactory.createOAuth2Request(clientDetails,
        defaultOAuth2RequestFactory.createTokenRequest(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters), "")));
  }

  @Test
  public void testCreateOAuth2RequestNoClientInRequest() {
    when(clientDetails.getClientId()).thenReturn("id");
    assertNotNull(defaultOAuth2RequestFactory.createTokenRequest(Map.of(), clientDetails));
  }

  @Test
  public void createOAuth2RequestWithUserCheck() {
    defaultOAuth2RequestFactory.setCheckUserScopes(true);
    assertNotNull(defaultOAuth2RequestFactory.createOAuth2Request(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters)));
    SecurityContextAccessor securityContextAccessor = mock(SecurityContextAccessor.class);
    defaultOAuth2RequestFactory.setSecurityContextAccessor(securityContextAccessor);
    when(securityContextAccessor.isUser()).thenReturn(true);
    assertNotNull(defaultOAuth2RequestFactory.createOAuth2Request(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters)));
  }

  @Test
  public void createOAuth2RequestWithUserCheckAndScopes() {
    SecurityContextAccessor securityContextAccessor = mock(SecurityContextAccessor.class);
    defaultOAuth2RequestFactory.setSecurityContextAccessor(securityContextAccessor);
    defaultOAuth2RequestFactory.setCheckUserScopes(true);
    when(securityContextAccessor.isUser()).thenReturn(true);
    when(clientDetails.getScope()).thenReturn(Set.of("read", "uaa", "admin"));
    Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("read,write");
    doReturn(authorities).when(securityContextAccessor).getAuthorities();
    assertNotNull(defaultOAuth2RequestFactory.createOAuth2Request(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters)));
  }
}
