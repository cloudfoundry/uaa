package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.AbstractOAuth2AccessTokenMatchers;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.singleton;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.mockito.Mockito.when;

public class RefreshRotationTest {

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  private TestTokenEnhancer tokenEnhancer;

  private CompositeToken persistToken;
  private Date expiration;

  private TokenTestSupport tokenSupport;
  private RevocableTokenProvisioning tokenProvisioning;

  private Calendar expiresAt = Calendar.getInstance();
  private Calendar updatedAt = Calendar.getInstance();
  private Set<String> acrValue = Sets.newHashSet("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

  private UaaTokenServices tokenServices;
  private KeyInfoService keyInfoService;

  @Before
  public void setUp() throws Exception {
    tokenSupport = new TokenTestSupport(tokenEnhancer);
    keyInfoService = new KeyInfoService("https://uaa.url");
    Set<String> thousandScopes = new HashSet<>();
    for (int i = 0; i < 1000; i++) {
      thousandScopes.add(String.valueOf(i));
    }
    persistToken = new CompositeToken("token-value");
    expiration = new Date(System.currentTimeMillis() + 10000);
    persistToken.setScope(thousandScopes);
    persistToken.setExpiration(expiration);

    tokenServices = tokenSupport.getUaaTokenServices();
    tokenServices.setKeyInfoService(keyInfoService);
    tokenProvisioning = tokenSupport.getTokenProvisioning();
    when(tokenSupport.timeService.getCurrentTimeMillis()).thenReturn(1000L);
  }

  @After
  public void teardown() {
    AbstractOAuth2AccessTokenMatchers.revocableTokens.remove();
    IdentityZoneHolder.clear();
    tokenSupport.clear();
  }

  @Test
  public void refreshRotation() {
    BaseClientDetails clientDetails = new BaseClientDetails(tokenSupport.defaultClient);
    clientDetails.setAutoApproveScopes(singleton("true"));
    tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));
    AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
    authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
    Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
    azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
    authorizationRequest.setRequestParameters(azParameters);
    Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

    OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
    CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(authentication);
    String refreshTokenValue = accessToken.getRefreshToken().getValue();
    assertThat(refreshTokenValue, is(notNullValue()));
    OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
    assertThat(refreshedToken, is(notNullValue()));
    assertEquals(refreshTokenValue, refreshedToken.getRefreshToken().getValue());
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(true);
    refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
    assertNotEquals(refreshTokenValue, refreshedToken.getRefreshToken().getValue());
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(false);
    new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.JWT.getStringValue());
  }
}
