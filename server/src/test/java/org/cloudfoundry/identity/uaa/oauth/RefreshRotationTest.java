package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.AbstractOAuth2AccessTokenMatchers;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.singleton;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_AUTH_METHOD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_EMPTY;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RefreshRotationTest {
  private CompositeToken persistToken;
  private Date expiration;
  private TokenTestSupport tokenSupport;
  private UaaTokenServices tokenServices;

  @BeforeEach
  void setUp() throws Exception {
    tokenSupport = new TokenTestSupport(null, null);
    when(tokenSupport.timeService.getCurrentDate()).thenCallRealMethod();
    when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
    Set<String> thousandScopes = new HashSet<>();
    for (int i = 0; i < 1000; i++) {
      thousandScopes.add(String.valueOf(i));
    }
    persistToken = new CompositeToken("token-value");
    expiration = new Date(System.currentTimeMillis() + 10000);
    persistToken.setScope(thousandScopes);
    persistToken.setExpiration(expiration);

    tokenServices = tokenSupport.getUaaTokenServices();
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
  }

  @AfterEach
  void teardown() {
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(false);
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.JWT.getStringValue());
    AbstractOAuth2AccessTokenMatchers.revocableTokens.remove();
    IdentityZoneHolder.clear();
    tokenSupport.clear();
    SecurityContextHolder.clearContext();
  }

  @Test
  @DisplayName("Refresh Token with rotation")
  void testRefreshRotation() {
    UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
    clientDetails.setAutoApproveScopes(singleton("true"));
    tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));
    AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
    authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
    Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
    azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
    authorizationRequest.setRequestParameters(azParameters);
    Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
    OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
    CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(authentication);

    String refreshTokenValue = accessToken.getRefreshToken().getValue();
    assertThat(refreshTokenValue, is(notNullValue()));

    OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
    assertThat(refreshedToken, is(notNullValue()));
    assertEquals("New refresh token should be equal to the old one.", refreshTokenValue, refreshedToken.getRefreshToken().getValue());

    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(true);

    Map<String, RevocableToken> tokens = tokenSupport.tokens;
    refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
    assertNotEquals("New access token should be different from the old one.", refreshTokenValue, refreshedToken.getRefreshToken().getValue());

  }

  @Test
  @DisplayName("Refresh Token with allowpublic and rotation")
  void testRefreshPublicClientWithRotation() {
    UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
    clientDetails.setAutoApproveScopes(singleton("true"));
    tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));
    AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
    authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
    Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
    azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
    authorizationRequest.setRequestParameters(azParameters);
    authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
    OAuth2Request oAuth2Request = authorizationRequest.createOAuth2Request();
    OAuth2Authentication authentication = new OAuth2Authentication(oAuth2Request, tokenSupport.defaultUserAuthentication);
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(true);
    CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(authentication);

    assertThat((Map<String, Object>) UaaTokenUtils.getClaims(accessToken.getValue(), Map.class), hasEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
    String refreshTokenValue = accessToken.getRefreshToken().getValue();
    assertThat(refreshTokenValue, is(notNullValue()));

    setupOAuth2Authentication(oAuth2Request);
    OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
    assertThat(refreshedToken, is(notNullValue()));
    assertNotEquals("New access token should be different from the old one.", refreshTokenValue, refreshedToken.getRefreshToken().getValue());
    assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class), hasEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));

    refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
    assertNotEquals("New access token should be different from the old one.", refreshTokenValue, refreshedToken.getRefreshToken().getValue());
    assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class), hasEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
  }

  @Test
  @DisplayName("Refresh Token from public to empty authentication")
  void testRefreshPublicClientWithRotationAndEmpyAuthentication() {
    UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
    clientDetails.setAutoApproveScopes(singleton("true"));
    tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));
    AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
    authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
    Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
    azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
    authorizationRequest.setRequestParameters(azParameters);
    authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
    OAuth2Request oAuth2Request = authorizationRequest.createOAuth2Request();
    OAuth2Authentication authentication = new OAuth2Authentication(oAuth2Request, tokenSupport.defaultUserAuthentication);
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(true);
    CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(authentication);

    assertThat((Map<String, Object>) UaaTokenUtils.getClaims(accessToken.getValue(), Map.class), hasEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
    String refreshTokenValue = accessToken.getRefreshToken().getValue();
    assertThat(refreshTokenValue, is(notNullValue()));

    authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_EMPTY));
    setupOAuth2Authentication(authorizationRequest.createOAuth2Request());
    OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
    assertThat(refreshedToken, is(notNullValue()));
    assertNotEquals("New access token should be different from the old one.", refreshTokenValue, refreshedToken.getRefreshToken().getValue());
    assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class), hasEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));

    refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
    assertNotEquals("New access token should be different from the old one.", refreshTokenValue, refreshedToken.getRefreshToken().getValue());
    assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class), hasEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
  }

  @Test
  @DisplayName("Refresh Token with allowpublic but without rotation")
  void testRefreshPublicClientWithoutRotation() {
    UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
    clientDetails.setAutoApproveScopes(singleton("true"));
    tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));
    AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
    authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
    Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
    azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
    authorizationRequest.setRequestParameters(azParameters);
    authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
    OAuth2Request oAuth2Request = authorizationRequest.createOAuth2Request();
    OAuth2Authentication authentication = new OAuth2Authentication(oAuth2Request, tokenSupport.defaultUserAuthentication);
    CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(authentication);

    assertThat((Map<String, Object>) UaaTokenUtils.getClaims(accessToken.getValue(), Map.class), hasEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
    String refreshTokenValue = accessToken.getRefreshToken().getValue();
    assertThat(refreshTokenValue, is(notNullValue()));

    setupOAuth2Authentication(oAuth2Request);
    RuntimeException exception = assertThrows(TokenRevokedException.class, () ->
        tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN)));
    assertEquals("Refresh without client authentication not allowed.", exception.getMessage());
  }

  @Test
  @DisplayName("Refresh with allowpublic and rotation but existing token was not public")
  void testRefreshPublicClientButExistingTokenWasEmptyAuthentication() {
    UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
    clientDetails.setAutoApproveScopes(singleton("true"));
    tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));
    AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
    authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
    Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
    azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
    authorizationRequest.setRequestParameters(azParameters);
    authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_EMPTY));
    OAuth2Request oAuth2Request = authorizationRequest.createOAuth2Request();
    OAuth2Authentication authentication = new OAuth2Authentication(oAuth2Request, tokenSupport.defaultUserAuthentication);
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(true);
    CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(authentication);

    assertThat((Map<String, Object>) UaaTokenUtils.getClaims(accessToken.getValue(), Map.class), hasEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
    String refreshTokenValue = accessToken.getRefreshToken().getValue();
    assertThat(refreshTokenValue, is(notNullValue()));

    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(false);
    authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
    setupOAuth2Authentication(authorizationRequest.createOAuth2Request());
    RuntimeException exception = assertThrows(TokenRevokedException.class, () ->
        tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN)));
    assertEquals("Refresh without client authentication not allowed.", exception.getMessage());
  }

  private static Authentication setupOAuth2Authentication(OAuth2Request auth2Request) {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    when(authentication.getOAuth2Request()).thenReturn(auth2Request);
    return authentication;
  }
}
