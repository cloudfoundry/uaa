package org.cloudfoundry.identity.uaa.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalService;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.openid.IdToken;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.openid.UserAuthenticationData;
import org.cloudfoundry.identity.uaa.oauth.refresh.CompositeExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.token.*;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.AbstractOAuth2AccessTokenMatchers;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2RefreshTokenMatchers;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TokenValidation;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.*;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.*;

import static java.util.Collections.*;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.*;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.*;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.*;
import static org.cloudfoundry.identity.uaa.user.UaaAuthority.USER_AUTHORITIES;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.AllOf.allOf;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.hamcrest.number.OrderingComparison.lessThanOrEqualTo;
import static org.hamcrest.text.IsEmptyString.isEmptyString;
import static org.junit.Assert.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.*;

@RunWith(Parameterized.class)
public class DeprecatedUaaTokenServicesTests {
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

    public DeprecatedUaaTokenServicesTests(TestTokenEnhancer enhancer, String testname) {
        this.tokenEnhancer = enhancer;
    }

    @Parameterized.Parameters(name = "{index}: testname[{1}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{{null, "old behavior"}, {new TestTokenEnhancer(), "using enhancer"}});
    }

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
    public void test_opaque_tokens_are_persisted() {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(false);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(JWT.getStringValue());
        CompositeToken result = tokenServices.persistRevocableToken("id",
          persistToken,
          new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, "rid"),
          "clientId",
          "userId",
          true,
          true);

        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, times(2)).create(rt.capture(), anyString());
        assertNotNull(rt.getAllValues());
        assertThat(rt.getAllValues().size(), equalTo(2));
        assertNotNull(rt.getAllValues().get(0));
        assertEquals(RevocableToken.TokenType.ACCESS_TOKEN, rt.getAllValues().get(0).getResponseType());
        assertEquals(OPAQUE.getStringValue(), rt.getAllValues().get(0).getFormat());
        assertEquals("id", result.getValue());
        assertEquals(RevocableToken.TokenType.REFRESH_TOKEN, rt.getAllValues().get(1).getResponseType());
        assertEquals(OPAQUE.getStringValue(), rt.getAllValues().get(1).getFormat());
        assertEquals("rid", result.getRefreshToken().getValue());
    }

    @Test
    public void test_refresh_tokens_are_uniquely_persisted() {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenUnique(true);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(OPAQUE.getStringValue());
        tokenServices.persistRevocableToken("id",
          persistToken,
          new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, ""),
          "clientId",
          "userId",
          true,
          true);
        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, times(1)).deleteRefreshTokensForClientAndUserId("clientId", "userId", IdentityZoneHolder.get().getId());
        verify(tokenProvisioning, times(2)).create(rt.capture(), anyString());
        RevocableToken refreshToken = rt.getAllValues().get(1);
        assertEquals(RevocableToken.TokenType.REFRESH_TOKEN, refreshToken.getResponseType());
    }

    @Test
    public void test_refresh_token_not_unique_when_set_to_false() {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenUnique(false);
        tokenServices.persistRevocableToken("id",
          persistToken,
          new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, ""),
          "clientId",
          "userId",
          true,
          true);
        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        String currentZoneId = IdentityZoneHolder.get().getId();
        verify(tokenProvisioning, times(0)).deleteRefreshTokensForClientAndUserId(anyString(), anyString(), eq(currentZoneId));
        verify(tokenProvisioning, times(2)).create(rt.capture(), anyString());
        RevocableToken refreshToken = rt.getAllValues().get(1);
        assertEquals(RevocableToken.TokenType.REFRESH_TOKEN, refreshToken.getResponseType());
    }

    @Test
    public void refreshAccessToken_buildsIdToken_withRolesAndAttributesAndACR() throws Exception {
        IdTokenCreator idTokenCreator = mock(IdTokenCreator.class);
        when(idTokenCreator.create(any(), any(), any())).thenReturn(mock(IdToken.class));

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setScope(Sets.newHashSet("openid"));

        MultitenantClientServices mockMultitenantClientServices = mock(MultitenantClientServices.class);
        when(mockMultitenantClientServices.loadClientByClientId(eq(TokenTestSupport.CLIENT_ID)))
          .thenReturn(clientDetails);

        TokenValidityResolver tokenValidityResolver = mock(TokenValidityResolver.class);
        when(tokenValidityResolver.resolve(TokenTestSupport.CLIENT_ID)).thenReturn(new Date());

        TokenValidation tokenValidation = mock(TokenValidation.class);
        TokenValidationService tokenValidationService = mock(TokenValidationService.class);
        when(tokenValidationService.validateToken(anyString(), anyBoolean())).thenReturn(tokenValidation);
        HashMap<String, Object> claims = Maps.newHashMap();
        String userId = "userid";
        claims.put(ClaimConstants.USER_ID, userId);
        claims.put(ClaimConstants.CID, TokenTestSupport.CLIENT_ID);
        claims.put(ClaimConstants.EXP, 1);
        claims.put(ClaimConstants.GRANTED_SCOPES, Lists.newArrayList("read", "write", "openid"));
        claims.put(ClaimConstants.GRANT_TYPE, "password");
        claims.put(ClaimConstants.AUD, Lists.newArrayList(TokenTestSupport.CLIENT_ID));
        HashMap<Object, Object> acrMap = Maps.newHashMap();
        acrMap.put(IdToken.ACR_VALUES_KEY, acrValue);
        claims.put(ClaimConstants.ACR, acrMap);
        when(tokenValidation.getClaims()).thenReturn(claims);
        when(tokenValidation.checkJti()).thenReturn(tokenValidation);
        Jwt jwt = mock(Jwt.class);
        when(tokenValidation.getJwt()).thenReturn(jwt);
        when(jwt.getEncoded()).thenReturn("encoded");

        UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
        UaaUser user = new UaaUser(new UaaUserPrototype().withId(userId).withUsername("marissa").withEmail("marissa@example.com"));
        when(userDatabase.retrieveUserById(userId))
          .thenReturn(user);

        ArgumentCaptor<UserAuthenticationData> userAuthenticationDataArgumentCaptor =
          ArgumentCaptor.forClass(UserAuthenticationData.class);

        TimeService timeService = mock(TimeService.class);
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        when(timeService.getCurrentDate()).thenCallRealMethod();
        ApprovalService approvalService = mock(ApprovalService.class);
        UaaTokenServices uaaTokenServices = new UaaTokenServices(
          idTokenCreator,
          mock(TokenEndpointBuilder.class),
          mockMultitenantClientServices,
          mock(RevocableTokenProvisioning.class),
          tokenValidationService,
          mock(RefreshTokenCreator.class),
          timeService,
          tokenValidityResolver,
          userDatabase,
          Sets.newHashSet(),
          new TokenPolicy(),
          new KeyInfoService(DEFAULT_ISSUER),
          new IdTokenGranter(approvalService),
          approvalService
        );

        UserInfo userInfo = new UserInfo();
        userInfo.setRoles(Lists.newArrayList("custom_role"));
        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        userAttributes.put("multi_value", Arrays.asList("value1", "value2"));
        userAttributes.add("single_value", "value3");

        userInfo.setUserAttributes(userAttributes);
        when(userDatabase.getUserInfo(userId)).thenReturn(userInfo);

        String refreshToken = getOAuth2AccessToken().getRefreshToken().getValue();
        uaaTokenServices.refreshAccessToken(refreshToken, getRefreshTokenRequest());

        verify(idTokenCreator).create(eq(clientDetails), eq(user), userAuthenticationDataArgumentCaptor.capture());
        UserAuthenticationData userData = userAuthenticationDataArgumentCaptor.getValue();
        Set<String> expectedRoles = Sets.newHashSet("custom_role");
        assertEquals(expectedRoles, userData.roles);
        assertEquals(userAttributes, userData.userAttributes);
        assertEquals(acrValue, userData.contextClassRef);
    }

    @Test
    public void test_jwt_no_token_is_not_persisted() {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(JWT.getStringValue());
        CompositeToken result = tokenServices.persistRevocableToken("id",
          persistToken,
          new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, ""),
          "clientId",
          "userId",
          false,
          false);

        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, never()).create(rt.capture(), anyString());
        assertEquals(persistToken.getValue(), result.getValue());
        assertEquals("refresh-token-value", result.getRefreshToken().getValue());
    }

    @Test
    public void test_opaque_refresh_token_is_persisted() {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(OPAQUE.getStringValue());
        CompositeToken result = tokenServices.persistRevocableToken("id",
          persistToken,
          new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, ""),
          "clientId",
          "userId",
          false,
          false);

        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, times(1)).create(rt.capture(), anyString());
        assertNotNull(rt.getAllValues());
        assertEquals(1, rt.getAllValues().size());
        assertEquals(RevocableToken.TokenType.REFRESH_TOKEN, rt.getAllValues().get(0).getResponseType());
        assertEquals(OPAQUE.getStringValue(), rt.getAllValues().get(0).getFormat());
        assertEquals("refresh-token-value", rt.getAllValues().get(0).getValue());
        assertNotEquals("refresh-token-value", result.getRefreshToken().getValue());
    }

    @Test
    public void isOpaqueTokenRequired() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, TokenConstants.GRANT_TYPE_USER_TOKEN);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        assertTrue(tokenServices.isOpaqueTokenRequired(authentication));
    }

    @Test(expected = InvalidTokenException.class)
    public void testNullRefreshTokenString() {
        tokenServices.refreshAccessToken(null, null);
    }

    @Test
    public void testInvalidRefreshToken() {
        Map<String, String> map = new HashMap<>();
        map.put("grant_type", "refresh_token");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(map, null, null, null, null, null, false, null, null, null);
        String refreshTokenValue = "dasdasdasdasdas";
        try {
            tokenServices.refreshAccessToken(refreshTokenValue, tokenSupport.requestFactory.createTokenRequest(authorizationRequest, "refresh_token"));
            fail("Expected Exception was not thrown");
        } catch (InvalidTokenException e) {
            assertThat(e.getMessage(), not(containsString(refreshTokenValue)));
        }
    }

    @Test
    public void misconfigured_keys_throws_proper_error() {
        expectedException.expect(InternalAuthenticationServiceException.class);
        expectedException.expectMessage("Unable to sign token, misconfigured JWT signing keys");
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("invalid");
        performPasswordGrant(JWT.getStringValue());
    }

    @Test
    public void testCreateAccessTokenForAClient() {

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken, validFor(is(tokenSupport.accessTokenValidity)));
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, zoneId(is(IdentityZoneHolder.get().getId())));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));
        validateExternalAttributes(accessToken);

        assertCommonEventProperties(accessToken, CLIENT_ID, tokenSupport.expectedJson);
    }

    @Test
    public void testCreateAccessTokenForAnotherIssuer() throws Exception {
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        identityZone.setConfig(
          JsonUtils.readValue(
            "{\"issuer\": \"http://uaamaster:8080/uaa\"}",
            IdentityZoneConfiguration.class
          )
        );
        identityZone.getConfig().getTokenPolicy().setAccessTokenValidity(tokenSupport.accessTokenValidity);
        tokenSupport.copyClients(IdentityZoneHolder.get().getId(), identityZone.getId());
        IdentityZoneHolder.set(identityZone);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        tokenServices.setTokenEndpointBuilder(new TokenEndpointBuilder("http://uaaslave:8080/uaa"));
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken, validFor(is(tokenSupport.accessTokenValidity)));
        assertThat(accessToken, issuerUri(is("http://uaamaster:8080/uaa/oauth/token")));
        assertThat(accessToken, zoneId(is(IdentityZoneHolder.get().getId())));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));
        validateExternalAttributes(accessToken);
    }

    @Test
    public void testCreateAccessTokenForInvalidIssuer() {
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        try {
            identityZone.setConfig(
              JsonUtils.readValue(
                "{\"issuer\": \"notAnURL\"}",
                IdentityZoneConfiguration.class
              )
            );
            fail();
        } catch (JsonUtils.JsonUtilException e) {
            assertThat(e.getMessage(), containsString("Invalid issuer format. Must be valid URL."));
        }
    }

    @Test
    public void test_refresh_token_is_opaque_when_requested() {
        OAuth2AccessToken accessToken = performPasswordGrant(OPAQUE.getStringValue());
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();

        String refreshTokenValue = accessToken.getRefreshToken().getValue();
        assertThat("Token value should be equal to or lesser than 36 characters", refreshTokenValue.length(), lessThanOrEqualTo(36));
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));
        TokenRequest refreshTokenRequest = getRefreshTokenRequest();

        //validate both opaque and JWT refresh tokenSupport.tokens
        for (String s : Arrays.asList(refreshTokenValue, tokenSupport.tokens.get(refreshTokenValue).getValue())) {
            OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(s, refreshTokenRequest);
            assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        }
    }

    @Test
    public void test_using_opaque_parameter_on_refresh_grant() {
        OAuth2AccessToken accessToken = performPasswordGrant(OPAQUE.getStringValue());
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        String refreshTokenValue = refreshToken.getValue();

        Map<String, String> parameters = new HashMap<>();
        parameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        TokenRequest refreshTokenRequest = getRefreshTokenRequest(parameters);

        //validate both opaque and JWT refresh tokenSupport.tokens
        for (String s : Arrays.asList(refreshTokenValue, tokenSupport.tokens.get(refreshTokenValue).getValue())) {
            OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(s, refreshTokenRequest);
            assertThat("Token value should be equal to or lesser than 36 characters", refreshedAccessToken.getValue().length(), lessThanOrEqualTo(36));
            assertCommonUserAccessTokenProperties(new DefaultOAuth2AccessToken(tokenSupport.tokens.get(refreshedAccessToken).getValue()), CLIENT_ID);
            validateExternalAttributes(refreshedAccessToken);
        }
    }

    @Test
    public void testCreateOpaqueAccessTokenForAClient() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertTrue("Token is not a composite token", accessToken instanceof CompositeToken);
        assertThat("Token value should be equal to or lesser than 36 characters", accessToken.getValue().length(), lessThanOrEqualTo(36));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));
    }

    @Test
    public void testCreateAccessTokenForAClientInAnotherIdentityZone() {
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        identityZone.setConfig(
          JsonUtils.readValue(
            "{\"tokenPolicy\":{\"accessTokenValidity\":3600,\"refreshTokenValidity\":7200}}",
            IdentityZoneConfiguration.class
          )
        );
        tokenSupport.copyClients(IdentityZoneHolder.get().getId(), identityZone.getId());
        IdentityZoneHolder.set(identityZone);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        useIZMIforAccessToken(tokenServices);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken, validFor(is(3600)));
        assertThat(accessToken, issuerUri(is("http://" + subdomain + ".localhost:8080/uaa/oauth/token")));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));
        validateExternalAttributes(accessToken);

        Assert.assertEquals(1, tokenSupport.publisher.getEventCount());

        this.assertCommonEventProperties(accessToken, CLIENT_ID, tokenSupport.expectedJson);
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        authorizationRequest.setResponseTypes(Sets.newHashSet("id_token"));
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        Approval approval = new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(OPENID)
                .setExpiresAt(new Date())
                .setStatus(ApprovalStatus.APPROVED);
        tokenSupport.approvalStore.addApproval(approval, IdentityZone.getUaaZoneId());

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        CompositeToken castAccessToken = (CompositeToken) accessToken;
        assertThat(castAccessToken.getIdTokenValue(), is(notNullValue()));
        validateAccessAndRefreshToken(accessToken);
    }

    @Test
    public void testCreateAccessTokenOnlyForClientWithoutRefreshToken() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID_NO_REFRESH_TOKEN_GRANT, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        validateAccessTokenOnly(accessToken, CLIENT_ID_NO_REFRESH_TOKEN_GRANT);
        assertNull(accessToken.getRefreshToken());
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrantSwitchedPrimaryKey() {
        String originalPrimaryKeyId = tokenSupport.tokenPolicy.getActiveKeyId();
        try {
            tokenSupport.tokenPolicy.setActiveKeyId("otherKey");

            AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
            authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
            Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
            azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
            authorizationRequest.setRequestParameters(azParameters);
            Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

            OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

            validateAccessAndRefreshToken(accessToken);
        } finally {
            tokenSupport.tokenPolicy.setActiveKeyId(originalPrimaryKeyId);
        }
    }

    @Test
    public void testCreateAccessTokenPasswordGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        validateAccessAndRefreshToken(accessToken);
        tokenServices.loadAuthentication(accessToken.getValue());

        //ensure that we can load without user_name claim
        tokenServices.setExcludedClaims(new HashSet(Arrays.asList(ClaimConstants.AUTHORITIES, ClaimConstants.USER_NAME, ClaimConstants.EMAIL)));
        accessToken = tokenServices.createAccessToken(authentication);
        assertNotNull(tokenServices.loadAuthentication(accessToken.getValue()).getUserAuthentication());
    }

    @Test
    public void test_missing_required_user_groups() {

        tokenSupport.defaultClient.addAdditionalInformation(REQUIRED_USER_GROUPS, singletonList("uaa.admin"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("User does not meet the client's required group criteria.");
        tokenServices.createAccessToken(authentication);
    }

    @Test
    public void testClientSecret_Added_Token_Validation_Still_Works() {

        tokenSupport.defaultClient.setClientSecret(SECRET);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        //normal token validation
        tokenServices.loadAuthentication(accessToken.getValue());

        //add a 2nd secret
        tokenSupport.defaultClient.setClientSecret(tokenSupport.defaultClient.getClientSecret() + " newsecret");
        tokenServices.loadAuthentication(accessToken.getValue());

        //generate a token when we have two secrets
        OAuth2AccessToken accessToken2 = tokenServices.createAccessToken(authentication);

        //remove the 1st secret
        tokenSupport.defaultClient.setClientSecret("newsecret");
        try {
            tokenServices.loadAuthentication(accessToken.getValue());
            fail("Token should fail to validate on the revocation signature");
        } catch (InvalidTokenException e) {
            assertTrue(e.getMessage().contains("revocable signature mismatch"));
        }
        tokenServices.loadAuthentication(accessToken2.getValue());

        OAuth2AccessToken accessToken3 = tokenServices.createAccessToken(authentication);
        tokenServices.loadAuthentication(accessToken3.getValue());
    }

    @Test
    public void testCreateRevocableAccessTokenPasswordGrant() {
        OAuth2AccessToken accessToken = performPasswordGrant();

        validateAccessAndRefreshToken(accessToken);
    }

    @Test
    public void testCreateAccessTokenExternalContext() {
        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        TokenRequest refreshTokenRequest = getRefreshTokenRequest();
        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshTokenRequest);

        validateExternalAttributes(accessToken);
        validateExternalAttributes(refreshedAccessToken);
    }

    @Test
    public void testCreateAccessTokenRefreshGrant() {
        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        TokenRequest refreshTokenRequest = getRefreshTokenRequest();

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshTokenRequest);

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        validateExternalAttributes(accessToken);
    }

    @Test
    public void testCreateAccessTokenRefreshGrant_with_an_old_refresh_token_format_containing_scopes_claim() {
        //Given
        OAuth2AccessToken accessToken = getOAuth2AccessToken();
        String refreshTokenJwt = accessToken.getRefreshToken().getValue();

        String kid = JwtHelper.decode(refreshTokenJwt).getHeader().getKid();
        HashMap claimsWithScopeAndNotGrantedScopeMap = JsonUtils.readValue(JwtHelper.decode(refreshTokenJwt).getClaims(), HashMap.class);
        claimsWithScopeAndNotGrantedScopeMap.put("scope", Arrays.asList("openid", "read", "write"));
        claimsWithScopeAndNotGrantedScopeMap.remove("granted_scopes");

        Map<String, Object> tokenJwtHeaderMap = new HashMap<>();
        tokenJwtHeaderMap.put("alg", JwtHelper.decode(refreshTokenJwt).getHeader().getAlg());
        tokenJwtHeaderMap.put("kid", JwtHelper.decode(refreshTokenJwt).getHeader().getKid());
        tokenJwtHeaderMap.put("typ", JwtHelper.decode(refreshTokenJwt).getHeader().getTyp());

        String refreshTokenWithOnlyScopeClaimNotGrantedScopeClaim = UaaTokenUtils.constructToken(tokenJwtHeaderMap, claimsWithScopeAndNotGrantedScopeMap, keyInfoService.getKey(kid).getSigner());

        //When
        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(refreshTokenWithOnlyScopeClaimNotGrantedScopeClaim, getRefreshTokenRequest());

        //Then
        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        validateExternalAttributes(accessToken);
    }

    @Test
    public void createAccessToken_usingRefreshGrant_inOtherZone() {
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        identityZone.setConfig(
          JsonUtils.readValue(
            "{\"tokenPolicy\":{\"accessTokenValidity\":3600,\"refreshTokenValidity\":9600}}",
            IdentityZoneConfiguration.class
          )
        );
        tokenSupport.copyClients(IdentityZoneHolder.get().getId(), identityZone.getId());
        IdentityZoneHolder.set(identityZone);

        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);
        useIZMIforAccessToken(tokenServices);
        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
        assertThat(refreshedAccessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(3600)));
        validateExternalAttributes(accessToken);
    }

    @Test
    public void testCreateAccessTokenRefreshGrantAllScopesAutoApproved() {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        tokenSupport.clientDetailsService.setClientDetailsStore(
          IdentityZoneHolder.get().getId(),
          Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        // NO APPROVALS REQUIRED

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantSomeScopesAutoApprovedDowngradedRequest() {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        tokenSupport.clientDetailsService.setClientDetailsStore(
          IdentityZoneHolder.get().getId(),
          Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        // NO APPROVALS REQUIRED

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.readScope);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantSomeScopesAutoApproved() {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(tokenSupport.readScope);
        tokenSupport.clientDetailsService.setClientDetailsStore(
          IdentityZoneHolder.get().getId(),
          Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(OPENID)
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test(expected = InvalidTokenException.class)
    public void testCreateAccessTokenRefreshGrantNoScopesAutoApprovedIncompleteApprovals() {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(emptyList());
        tokenSupport.clientDetailsService.setClientDetailsStore(
          IdentityZoneHolder.get().getId(),
          Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantAllScopesAutoApprovedButApprovalDenied() {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(tokenSupport.requestedAuthScopes);
        tokenSupport.clientDetailsService.setClientDetailsStore(
          IdentityZoneHolder.get().getId(),
          Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.DENIED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
        assertNotNull(refreshedAccessToken);
    }

    @Test
    public void testCreateAccessTokenImplicitGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_IMPLICIT);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));
    }

    @Test
    public void create_id_token_with_roles_scope() {
        Jwt idTokenJwt = getIdToken(singletonList(OPENID));
        assertTrue(idTokenJwt.getClaims().contains("\"amr\":[\"ext\",\"rba\",\"mfa\"]"));
    }

    @Test
    public void create_id_token_with_amr_claim() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertTrue(idTokenJwt.getClaims().contains("\"amr\":[\"ext\",\"rba\",\"mfa\"]"));
    }

    @Test
    public void create_id_token_with_acr_claim() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertTrue(idTokenJwt.getClaims().contains("\"" + ClaimConstants.ACR + "\":{\"values\":[\""));
    }

    @Test
    public void create_id_token_without_roles_scope() {
        Jwt idTokenJwt = getIdToken(singletonList(OPENID));
        assertFalse(idTokenJwt.getClaims().contains("\"roles\""));
    }

    @Test
    public void create_id_token_with_profile_scope() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, PROFILE));
        assertTrue(idTokenJwt.getClaims().contains("\"given_name\":\"" + tokenSupport.defaultUser.getGivenName() + "\""));
        assertTrue(idTokenJwt.getClaims().contains("\"family_name\":\"" + tokenSupport.defaultUser.getFamilyName() + "\""));
        assertTrue(idTokenJwt.getClaims().contains("\"phone_number\":\"" + tokenSupport.defaultUser.getPhoneNumber() + "\""));
    }

    @Test
    public void create_id_token_without_profile_scope() {
        Jwt idTokenJwt = getIdToken(singletonList(OPENID));
        assertFalse(idTokenJwt.getClaims().contains("\"given_name\":"));
        assertFalse(idTokenJwt.getClaims().contains("\"family_name\":"));
        assertFalse(idTokenJwt.getClaims().contains("\"phone_number\":"));
    }

    @Test
    public void create_id_token_with_last_logon_time_claim() {
        Jwt idTokenJwt = getIdToken(singletonList(OPENID));
        assertTrue(idTokenJwt.getClaims().contains("\"previous_logon_time\":12365"));
    }

    @Test
    public void testCreateAccessWithNonExistingScopes() {
        List<String> scopesThatDontExist = Arrays.asList("scope1", "scope2");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, scopesThatDontExist);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_IMPLICIT);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(scopesThatDontExist)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(scopesThatDontExist));
    }

    @Test
    public void createAccessToken_forUser_inanotherzone() {
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        identityZone.setConfig(
          JsonUtils.readValue(
            "{\"tokenPolicy\":{\"accessTokenValidity\":3600,\"refreshTokenValidity\":9600}}",
            IdentityZoneConfiguration.class
          )
        );
        tokenSupport.copyClients(IdentityZone.getUaaZoneId(), identityZone.getId());
        IdentityZoneHolder.set(identityZone);


        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        useIZMIforAccessToken(tokenServices);
        useIZMIforRefreshToken(tokenServices);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken, issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken, validFor(is(3600)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(9600)));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrantNarrowerScopes() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());

        // First Request
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        assertThat(refreshToken, is(not(nullValue())));

        assertThat(refreshToken, OAuth2RefreshTokenMatchers.scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.audience(is(tokenSupport.resourceIds)));

        // Second request with reduced scopes
        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.readScope);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication reducedScopeAuthentication = new OAuth2Authentication(reducedScopeAuthorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken reducedScopeAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(reducedScopeAuthorizationRequest, "refresh_token"));

        // AT should have the new scopes, RT should be the same
        assertThat(reducedScopeAccessToken, scope(is(tokenSupport.readScope)));
        assertEquals(reducedScopeAccessToken.getRefreshToken(), accessToken.getRefreshToken());
    }

    @Test(expected = InvalidScopeException.class)
    public void testCreateAccessTokenAuthcodeGrantExpandedScopes() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        // First Request
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.audience(is(tokenSupport.resourceIds)));

        // Second request with expanded scopes
        AuthorizationRequest expandedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.expandedScopes);
        expandedScopeAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(expandedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        expandedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication expandedScopeAuthentication = new OAuth2Authentication(expandedScopeAuthorizationRequest.createOAuth2Request(), userAuthentication);
        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(expandedScopeAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testChangedExpiryForTokens() {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAccessTokenValiditySeconds(3600);
        clientDetails.setRefreshTokenValiditySeconds(36000);
        tokenSupport.clientDetailsService.setClientDetailsStore(
          IdentityZoneHolder.get().getId(),
          Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, validFor(is(3600)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.validFor(is(36000)));
    }

    @Test(expected = TokenRevokedException.class)
    public void testUserUpdatedAfterRefreshTokenIssued() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        UaaUser user = tokenSupport.userDatabase.retrieveUserByName(tokenSupport.username, OriginKeys.UAA);
        UaaUser newUser = new UaaUser(new UaaUserPrototype()
          .withId(tokenSupport.userId)
          .withUsername(user.getUsername())
          .withPassword("blah")
          .withEmail(user.getEmail())
          .withAuthorities(user.getAuthorities()));
        tokenSupport.userDatabase.updateUser(tokenSupport.userId, newUser);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testRefreshTokenExpiry() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());

        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        // Back date the refresh token. Crude way to do this but i'm not sure of
        // another
        clientDetails.setRefreshTokenValiditySeconds(-36000);
        tokenSupport.clientDetailsService.setClientDetailsStore(
          IdentityZoneHolder.get().getId(),
          Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        try {
            tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
            fail("Expected Exception was not thrown");
        } catch (InvalidTokenException e) {
            assertThat(e.getMessage(), not(containsString(accessToken.getRefreshToken().getValue())));
        }
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsRevoked() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());

        // Other scope is left unapproved

        for (Approval approval : tokenSupport.approvalStore.getApprovals(tokenSupport.userId, CLIENT_ID, IdentityZoneHolder.get().getId())) {
            tokenSupport.approvalStore.revokeApproval(approval, IdentityZoneHolder.get().getId());
        }

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsExpired() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsDenied() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.DENIED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsMissing() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.DENIED), IdentityZoneHolder.get().getId());

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsMissing2() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testReadAccessToken() {
        readAccessToken(EMPTY_SET);
    }

    @Test
    public void testReadAccessToken_No_PII() {
        readAccessToken(new HashSet<>(Arrays.asList(ClaimConstants.EMAIL, ClaimConstants.USER_NAME)));
    }

    @Test
    public void testReadAccessToken_When_Given_Refresh_token_should_throw_exception() {
        tokenServices.setExcludedClaims(new HashSet<>(Arrays.asList(ClaimConstants.EMAIL, ClaimConstants.USER_NAME)));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        Calendar expiresAt1 = Calendar.getInstance();
        expiresAt1.add(Calendar.MILLISECOND, 3000);
        Calendar updatedAt1 = Calendar.getInstance();
        updatedAt1.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt1.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt1.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt1.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt1.getTime()), IdentityZoneHolder.get().getId());
        Approval approval = new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(OPENID)
          .setExpiresAt(expiresAt1.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt1.getTime());
        tokenSupport.approvalStore.addApproval(
          approval, IdentityZoneHolder.get().getId());

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);


        expectedException.expectMessage("The token does not bear a \"scope\" claim.");
        tokenServices.readAccessToken(accessToken.getRefreshToken().getValue());
    }

    @Test(expected = InvalidTokenException.class)
    public void testReadAccessTokenForDeletedUserId() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);
        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.tokenSupport.userDatabase.clear();
        assertEquals(accessToken, tokenServices.readAccessToken(accessToken.getValue()));
    }

    @Test
    public void testLoadAuthenticationForAUser() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertEquals(USER_AUTHORITIES, loadedAuthentication.getAuthorities());
        assertEquals(tokenSupport.username, loadedAuthentication.getName());
        UaaPrincipal uaaPrincipal = (UaaPrincipal) tokenSupport.defaultUserAuthentication.getPrincipal();
        assertEquals(uaaPrincipal, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertEquals(tokenSupport.username, userAuth.getName());
        assertEquals(uaaPrincipal, userAuth.getPrincipal());
        assertTrue(userAuth.isAuthenticated());
    }

    @Test
    public void load_Opaque_AuthenticationForAUser() {
        tokenSupport.defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        azParameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertTrue("Token should be composite token", accessToken instanceof CompositeToken);
        CompositeToken composite = (CompositeToken) accessToken;
        assertThat("id_token should be JWT, thus longer than 36 characters", composite.getIdTokenValue().length(), greaterThan(36));
        assertThat("Opaque access token must be shorter than 37 characters", accessToken.getValue().length(), lessThanOrEqualTo(36));
        assertThat("Opaque refresh token must be shorter than 37 characters", accessToken.getRefreshToken().getValue().length(), lessThanOrEqualTo(36));

        String accessTokenValue = tokenProvisioning.retrieve(composite.getValue(), IdentityZoneHolder.get().getId()).getValue();
        Map<String, Object> accessTokenClaims = tokenSupport.tokenValidationService.validateToken(accessTokenValue, true).getClaims();
        assertTrue((Boolean) accessTokenClaims.get(ClaimConstants.REVOCABLE));

        String refreshTokenValue = tokenProvisioning.retrieve(composite.getRefreshToken().getValue(), IdentityZoneHolder.get().getId()).getValue();
        Map<String, Object> refreshTokenClaims = tokenSupport.tokenValidationService.validateToken(refreshTokenValue, false).getClaims();
        assertTrue((Boolean) refreshTokenClaims.get(ClaimConstants.REVOCABLE));

        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertEquals(USER_AUTHORITIES, loadedAuthentication.getAuthorities());
        assertEquals(tokenSupport.username, loadedAuthentication.getName());
        UaaPrincipal uaaPrincipal = (UaaPrincipal) tokenSupport.defaultUserAuthentication.getPrincipal();
        assertEquals(uaaPrincipal, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertEquals(tokenSupport.username, userAuth.getName());
        assertEquals(uaaPrincipal, userAuth.getPrincipal());
        assertTrue(userAuth.isAuthenticated());

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "refresh_token");
        params.put("client_id", CLIENT_ID);
        params.put("token_format", OPAQUE.getStringValue());
        OAuth2AccessToken newAccessToken = tokenServices.refreshAccessToken(composite.getRefreshToken().getValue(), new TokenRequest(params, CLIENT_ID, Collections.EMPTY_SET, "refresh_token"));
        assertThat("Opaque access token must be shorter than 37 characters", newAccessToken.getValue().length(), lessThanOrEqualTo(36));
        assertThat("Opaque refresh token must be shorter than 37 characters", newAccessToken.getRefreshToken().getValue().length(), lessThanOrEqualTo(36));
    }

    @Test
    public void loadAuthentication_when_given_an_opaque_refreshToken_should_throw_exception() {
        tokenSupport.defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);

        azParameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());

        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken compositeToken = tokenServices.createAccessToken(authentication);

        String refreshTokenValue = tokenProvisioning.retrieve(compositeToken.getRefreshToken().getValue(), IdentityZoneHolder.get().getId()).getValue();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("The token does not bear a \"scope\" claim.");

        tokenServices.loadAuthentication(refreshTokenValue);
    }

    @Test
    public void loadAuthentication_when_given_an_refresh_jwt_should_throw_exception() {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(true);
        tokenSupport.defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);

        azParameters.put(REQUEST_TOKEN_FORMAT, JWT.getStringValue());

        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken compositeToken = tokenServices.createAccessToken(authentication);
        TokenValidation refreshToken = tokenSupport.tokenValidationService.validateToken(compositeToken.getRefreshToken().getValue(), false);

        String refreshTokenValue = tokenProvisioning.retrieve(refreshToken.getClaims().get("jti").toString(), IdentityZoneHolder.get().getId()).getValue();

        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("The token does not bear a \"scope\" claim.");
        tokenServices.loadAuthentication(refreshTokenValue);
    }

    @Test
    public void testLoadAuthenticationForAClient() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertThat("Client authorities match.",
          loadedAuthentication.getAuthorities(),
          containsInAnyOrder(AuthorityUtils.commaSeparatedStringToAuthorityList(CLIENT_AUTHORITIES).toArray())
        );
        assertEquals(CLIENT_ID, loadedAuthentication.getName());
        assertEquals(CLIENT_ID, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        assertNull(loadedAuthentication.getUserAuthentication());
    }

    @Test
    public void testLoadAuthenticationWithAnExpiredToken() {
        BaseClientDetails shortExpiryClient = tokenSupport.defaultClient;
        shortExpiryClient.setAccessTokenValiditySeconds(1);
        tokenSupport.clientDetailsService.setClientDetailsStore(
          IdentityZoneHolder.get().getId(),
          Collections.singletonMap(CLIENT_ID, shortExpiryClient)
        );

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThat(accessToken, validFor(is(1)));

        when(tokenSupport.timeService.getCurrentTimeMillis()).thenReturn(2001L);
        try {
            tokenServices.loadAuthentication(accessToken.getValue());
            fail("Expected Exception was not thrown");
        } catch (InvalidTokenException e) {
            assertThat(e.getMessage(), not(containsString(accessToken.getValue())));
        }
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrantAdditionalAuthorizationAttributes() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        azParameters.put("authorities", "{\"az_attr\":{\"external_group\":\"domain\\\\group1\", \"external_id\":\"abcd1234\"}}");
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken token = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(token, CLIENT_ID);
        assertThat(token, issuerUri(is(ISSUER_URI)));
        assertThat(token, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(token, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = token.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(token, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        Map<String, String> azMap = new LinkedHashMap<>();
        azMap.put("external_group", "domain\\group1");
        azMap.put("external_id", "abcd1234");
        assertEquals(azMap, token.getAdditionalInformation().get("az_attr"));
    }

    @Test
    public void testWrongClientDoesNotLeakToken() {
        AuthorizationRequest ar = mock(AuthorizationRequest.class);
        OAuth2AccessToken accessToken = getOAuth2AccessToken();
        TokenRequest refreshTokenRequest = getRefreshTokenRequest();
        try {
            refreshTokenRequest.setClientId("invalidClientForToken");
            tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshTokenRequest);
            fail();
        } catch (InvalidGrantException e) {
            assertThat(e.getMessage(), startsWith("Wrong client for this refresh token"));
            assertThat(e.getMessage(), not(containsString(accessToken.getRefreshToken().getValue())));
        }
    }

    @Test
    public void createRefreshToken_JwtDoesNotContainScopeClaim() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        Map<String, String> authzParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        authzParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authzParameters.put(REQUEST_TOKEN_FORMAT, JWT.toString());
        authorizationRequest.setRequestParameters(authzParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        String refreshTokenString = accessToken.getRefreshToken().getValue();
        assertNotNull(refreshTokenString);

        Claims refreshTokenClaims = getClaimsFromTokenString(refreshTokenString);
        assertNotNull(refreshTokenClaims);
        assertNull(refreshTokenClaims.getScope());
        // matcher below can't match list against set
        assertThat(refreshTokenClaims.getGrantedScopes(), containsInAnyOrder(accessToken.getScope().toArray()));
    }

    @Test
    public void refreshAccessToken_withAccessToken() {
        expectedException.expect(InvalidTokenException.class);
        expectedException.expectMessage("Invalid refresh token.");

        tokenServices.refreshAccessToken(getOAuth2AccessToken().getValue(), getRefreshTokenRequest());
    }

    private void readAccessToken(Set<String> excludedClaims) {
        tokenServices.setExcludedClaims(excludedClaims);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);
        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        Approval approval = new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(OPENID)
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime());
        tokenSupport.approvalStore.addApproval(
          approval, IdentityZoneHolder.get().getId());

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertEquals(accessToken, tokenServices.readAccessToken(accessToken.getValue()));

        tokenSupport.approvalStore.revokeApproval(approval, IdentityZoneHolder.get().getId());
        try {
            tokenServices.readAccessToken(accessToken.getValue());
            fail("Approval has been revoked");
        } catch (InvalidTokenException x) {
            assertThat("Exception should be about approvals", x.getMessage().contains("some requested scopes are not approved"));
        }
    }

    private Jwt getIdToken(List<String> scopes) {
        return tokenSupport.getIdToken(scopes);
    }

    private String buildJsonString(List<String> list) {
        StringBuffer buf = new StringBuffer("[");
        int count = list.size();
        for (String s : list) {
            buf.append("\"");
            buf.append(s);
            buf.append("\"");
            if (--count > 0) {
                buf.append(",");
            }
        }
        buf.append("]");
        return buf.toString();
    }

    private OAuth2AccessToken performPasswordGrant() {
        return performPasswordGrant(JWT.getStringValue());
    }

    private OAuth2AccessToken performPasswordGrant(String tokenFormat) {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        azParameters.put(REQUEST_TOKEN_FORMAT, tokenFormat);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        return tokenServices.createAccessToken(authentication);
    }

    private IdentityZone getIdentityZone(String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(subdomain);
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    private void validateAccessTokenOnly(OAuth2AccessToken accessToken, String clientId) {
        this.assertCommonUserAccessTokenProperties(accessToken, clientId);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        validateExternalAttributes(accessToken);
    }

    private void validateAccessAndRefreshToken(OAuth2AccessToken accessToken) {
        validateAccessTokenOnly(accessToken, CLIENT_ID);

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void validateExternalAttributes(OAuth2AccessToken accessToken) {
        Map<String, String> extendedAttributes = (Map<String, String>) accessToken.getAdditionalInformation().get(ClaimConstants.EXTERNAL_ATTR);
        if (tokenEnhancer != null) {
            String atValue = accessToken.getValue().length() < 40 ?
              tokenSupport.tokens.get(accessToken.getValue()).getValue() :
              accessToken.getValue();
            Map<String, Object> claims = JsonUtils.readValue(JwtHelper.decode(atValue).getClaims(),
              new TypeReference<Map<String, Object>>() {
              });

            assertNotNull(claims.get("ext_attr"));
            assertEquals("test", ((Map) claims.get("ext_attr")).get("purpose"));

            assertNotNull(claims.get("ex_prop"));
            assertEquals("nz", ((Map) claims.get("ex_prop")).get("country"));

            assertThat((List<String>) claims.get("ex_groups"), containsInAnyOrder("admin", "editor"));

        } else {
            assertNull("External attributes should not exist", extendedAttributes);
        }
    }

    private TokenRequest getRefreshTokenRequest() {
        return getRefreshTokenRequest(emptyMap());
    }

    private TokenRequest getRefreshTokenRequest(Map<String, String> requestParameters) {
        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        refreshAuthorizationRequest.setRequestParameters(requestParameters);
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);
        return tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token");
    }

    private OAuth2AccessToken getOAuth2AccessToken() {
        expiresAt.add(Calendar.MILLISECOND, 300000);
        updatedAt.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.readScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(tokenSupport.writeScope.get(0))
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
          .setUserId(tokenSupport.userId)
          .setClientId(CLIENT_ID)
          .setScope(OPENID)
          .setExpiresAt(expiresAt.getTime())
          .setStatus(ApprovalStatus.APPROVED)
          .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        return tokenServices.createAccessToken(authentication);
    }

    private BaseClientDetails cloneClient(ClientDetails client) {
        return new BaseClientDetails(client);
    }

    @SuppressWarnings("unchecked")
    private void assertCommonClientAccessTokenProperties(OAuth2AccessToken accessToken) {
        assertThat(accessToken, allOf(clientId(is(CLIENT_ID)),
          userId(is(nullValue())),
          subject(is(CLIENT_ID)),
          username(is(nullValue())),
          cid(is(CLIENT_ID)),
          scope(is(tokenSupport.clientScopes)),
          audience(is(tokenSupport.resourceIds)),
          jwtId(not(isEmptyString())),
          issuedAt(is(greaterThan(0))),
          expiry(is(greaterThan(0)))));
    }

    @SuppressWarnings({"unused", "unchecked"})
    private void assertCommonUserAccessTokenProperties(OAuth2AccessToken accessToken, String clientId) {
        assertThat(accessToken, allOf(username(is(tokenSupport.username)),
          clientId(is(clientId)),
          subject(is(tokenSupport.userId)),
          audience(is(tokenSupport.resourceIds)),
          origin(is(OriginKeys.UAA)),
          revocationSignature(is(not(nullValue()))),
          cid(is(clientId)),
          userId(is(tokenSupport.userId)),
          email(is(tokenSupport.email)),
          jwtId(not(isEmptyString())),
          issuedAt(is(greaterThan(0))),
          expiry(is(greaterThan(0)))
        ));
    }

    @SuppressWarnings("unchecked")
    private void assertCommonUserRefreshTokenProperties(OAuth2RefreshToken refreshToken) {
        assertThat(refreshToken, allOf(/*issuer(is(issuerUri)),*/
          OAuth2RefreshTokenMatchers.username(is(tokenSupport.username)),
          OAuth2RefreshTokenMatchers.clientId(is(CLIENT_ID)),
          OAuth2RefreshTokenMatchers.subject(is(not(nullValue()))),
          OAuth2RefreshTokenMatchers.audience(is(tokenSupport.resourceIds)),
          OAuth2RefreshTokenMatchers.origin(is(OriginKeys.UAA)),
          OAuth2RefreshTokenMatchers.revocationSignature(is(not(nullValue()))),
          OAuth2RefreshTokenMatchers.jwtId(not(isEmptyString())),
          OAuth2RefreshTokenMatchers.issuedAt(is(greaterThan(0))),
          OAuth2RefreshTokenMatchers.expiry(is(greaterThan(0)))
          )
        );
    }

    private void assertCommonEventProperties(OAuth2AccessToken accessToken, String expectedPrincipalId, String expectedData) {
        Assert.assertEquals(1, tokenSupport.publisher.getEventCount());

        TokenIssuedEvent event = tokenSupport.publisher.getLatestEvent();
        Assert.assertEquals(accessToken, event.getSource());
        Assert.assertEquals(tokenSupport.mockAuthentication, event.getAuthentication());
        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals(expectedPrincipalId, auditEvent.getPrincipalId());
        Assert.assertEquals(expectedData, auditEvent.getData());
        Assert.assertEquals(AuditEventType.TokenIssuedEvent, auditEvent.getType());
    }

    private Claims getClaimsFromTokenString(String token) {
        Jwt jwt = JwtHelper.decode(token);
        if (jwt == null) {
            return null;
        } else {
            return JsonUtils.readValue(jwt.getClaims(), Claims.class);
        }
    }

    private static void useIZMIforAccessToken(UaaTokenServices tokenServices) {
        TokenValidityResolver accessTokenValidityResolver =
                (TokenValidityResolver) ReflectionTestUtils.getField(tokenServices, "accessTokenValidityResolver");
        ClientTokenValidity clientTokenValidity =
                (ClientTokenValidity) ReflectionTestUtils.getField(accessTokenValidityResolver, "clientTokenValidity");
        ReflectionTestUtils.setField(clientTokenValidity, "identityZoneManager", new IdentityZoneManagerImpl());
    }

    private static void useIZMIforRefreshToken(UaaTokenServices tokenServices) {
        RefreshTokenCreator refreshTokenCreator =
                (RefreshTokenCreator) ReflectionTestUtils.getField(tokenServices, "refreshTokenCreator");
        TokenValidityResolver refreshTokenValidityResolver =
                (TokenValidityResolver) ReflectionTestUtils.getField(refreshTokenCreator, "refreshTokenValidityResolver");
        ClientTokenValidity clientTokenValidity =
                (ClientTokenValidity) ReflectionTestUtils.getField(refreshTokenValidityResolver, "clientTokenValidity");

        ReflectionTestUtils.setField(clientTokenValidity, "identityZoneManager", new IdentityZoneManagerImpl());
    }

}
