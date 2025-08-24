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
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.openid.IdToken;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.openid.UserAuthenticationData;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.refresh.CompositeExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.AbstractOAuth2AccessTokenMatchers;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2RefreshTokenMatchers;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.assertj.core.api.HamcrestCondition.matching;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_AUTHORITIES;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_ID_NO_REFRESH_TOKEN_GRANT;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.DEFAULT_ISSUER;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.ISSUER_URI;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.OPENID;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.PROFILE;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.audience;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.cid;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.clientId;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.email;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.expiry;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.issuedAt;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.issuerUri;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.jwtId;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.origin;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.revocationSignature;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.scope;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.subject;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.userId;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.username;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.validFor;
import static org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers.zoneId;
import static org.cloudfoundry.identity.uaa.user.UaaAuthority.USER_AUTHORITIES;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DeprecatedUaaTokenServicesTests {

    private TestTokenEnhancer tokenEnhancer;

    private CompositeToken persistToken;
    private Date expiration;

    private TokenTestSupport tokenSupport;
    private RevocableTokenProvisioning tokenProvisioning;

    private final Calendar expiresAt = Calendar.getInstance();
    private final Calendar updatedAt = Calendar.getInstance();
    private final Set<String> acrValue = Sets.newHashSet("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");

    private UaaTokenServices tokenServices;

    void initDeprecatedUaaTokenServicesTests(TestTokenEnhancer enhancer) {
        this.tokenEnhancer = enhancer;
        assertThatNoException().isThrownBy(() -> tokenSupport = new TokenTestSupport(tokenEnhancer, new KeyInfoService("https://uaa.url")));

        Set<String> thousandScopes = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            thousandScopes.add(String.valueOf(i));
        }
        persistToken = new CompositeToken("token-value");
        expiration = new Date(System.currentTimeMillis() + 10000);
        persistToken.setScope(thousandScopes);
        persistToken.setExpiration(expiration);

        tokenServices = tokenSupport.getUaaTokenServices();
        tokenProvisioning = tokenSupport.getTokenProvisioning();
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod().thenReturn(1000L);
    }

    public static Stream<Arguments> data() {
        return Stream.of(
                arguments(named("old behavior", null)),
                arguments(named("using enhancer", new TestTokenEnhancer()))
        );
    }

    @AfterEach
    void teardown() {
        AbstractOAuth2AccessTokenMatchers.revocableTokens.remove();
        IdentityZoneHolder.clear();
        tokenSupport.clear();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void equals(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        CompositeToken copyToken = new CompositeToken(persistToken);
        assertThat(persistToken).isEqualTo(copyToken)
                .hasSameHashCodeAs(copyToken);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void opaque_tokens_are_persisted(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(false);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(JWT.getStringValue());
        CompositeToken result = tokenServices.persistRevocableToken("id",
                persistToken,
                new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, "rid"),
                "clientId",
                "userId",
                true,
                true, null);

        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, times(1)).upsert(anyString(), rt.capture(), anyString());
        verify(tokenProvisioning, times(1)).createIfNotExists(rt.capture(), anyString());
        assertThat(rt.getAllValues()).hasSize(2);
        assertThat(rt.getAllValues().getFirst()).isNotNull();
        assertThat(rt.getAllValues().getFirst().getResponseType()).isEqualTo(RevocableToken.TokenType.ACCESS_TOKEN);
        assertThat(rt.getAllValues().getFirst().getFormat()).isEqualTo(OPAQUE.getStringValue());
        assertThat(result.getValue()).isEqualTo("id");
        assertThat(rt.getAllValues().get(1).getResponseType()).isEqualTo(RevocableToken.TokenType.REFRESH_TOKEN);
        assertThat(rt.getAllValues().get(1).getFormat()).isEqualTo(OPAQUE.getStringValue());
        assertThat(result.getRefreshToken().getValue()).isEqualTo("rid");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refresh_tokens_are_uniquely_persisted(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenUnique(true);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(OPAQUE.getStringValue());
        tokenServices.persistRevocableToken("id",
                persistToken,
                new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, ""),
                "clientId",
                "userId",
                true,
                true, null);
        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, times(1)).deleteRefreshTokensForClientAndUserId("clientId", "userId", IdentityZoneHolder.get().getId());
        verify(tokenProvisioning, times(1)).upsert(anyString(), rt.capture(), anyString());
        verify(tokenProvisioning, times(1)).createIfNotExists(rt.capture(), anyString());
        RevocableToken refreshToken = rt.getAllValues().get(1);
        assertThat(refreshToken.getResponseType()).isEqualTo(RevocableToken.TokenType.REFRESH_TOKEN);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refresh_token_not_unique_when_set_to_false(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenUnique(false);
        tokenServices.persistRevocableToken("id",
                persistToken,
                new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, ""),
                "clientId",
                "userId",
                true,
                true, null);
        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        String currentZoneId = IdentityZoneHolder.get().getId();
        verify(tokenProvisioning, times(0)).deleteRefreshTokensForClientAndUserId(anyString(), anyString(), eq(currentZoneId));
        verify(tokenProvisioning, times(1)).upsert(anyString(), rt.capture(), anyString());
        verify(tokenProvisioning, times(1)).createIfNotExists(rt.capture(), anyString());
        RevocableToken refreshToken = rt.getAllValues().get(1);
        assertThat(refreshToken.getResponseType()).isEqualTo(RevocableToken.TokenType.REFRESH_TOKEN);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refreshAccessToken_buildsIdToken_withRolesAndAttributesAndACR(TestTokenEnhancer enhancer) throws Exception {
        initDeprecatedUaaTokenServicesTests(enhancer);
        IdTokenCreator idTokenCreator = mock(IdTokenCreator.class);
        when(idTokenCreator.create(any(), any(), any(), any())).thenReturn(mock(IdToken.class));

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setScope(Sets.newHashSet("openid"));

        MultitenantClientServices mockMultitenantClientServices = mock(MultitenantClientServices.class);
        when(mockMultitenantClientServices.loadClientByClientId(TokenTestSupport.CLIENT_ID))
                .thenReturn(clientDetails);

        TokenValidityResolver tokenValidityResolver = mock(TokenValidityResolver.class);
        when(tokenValidityResolver.resolve(TokenTestSupport.CLIENT_ID)).thenReturn(new Date());

        JwtTokenSignedByThisUAA jwtToken = mock(JwtTokenSignedByThisUAA.class);
        TokenValidationService tokenValidationService = mock(TokenValidationService.class);
        when(tokenValidationService.validateToken(anyString(), anyBoolean())).thenReturn(jwtToken);
        HashMap<String, Object> claims = Maps.newHashMap();
        String userId = "userid";
        claims.put(ClaimConstants.USER_ID, userId);
        claims.put(ClaimConstants.CID, TokenTestSupport.CLIENT_ID);
        claims.put(ClaimConstants.EXPIRY_IN_SECONDS, 1);
        claims.put(ClaimConstants.GRANTED_SCOPES, Lists.newArrayList("read", "write", "openid"));
        claims.put(ClaimConstants.GRANT_TYPE, "password");
        claims.put(ClaimConstants.AUD, Lists.newArrayList(TokenTestSupport.CLIENT_ID));
        HashMap<Object, Object> acrMap = Maps.newHashMap();
        acrMap.put(IdToken.ACR_VALUES_KEY, acrValue);
        claims.put(ClaimConstants.ACR, acrMap);
        when(jwtToken.getClaims()).thenReturn(claims);
        when(jwtToken.checkJti()).thenReturn(jwtToken);
        Jwt jwt = mock(Jwt.class);
        when(jwtToken.getJwt()).thenReturn(jwt);
        when(jwt.getEncoded()).thenReturn("encoded");

        UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
        UaaUserPrototype uaaUserPrototype = new UaaUserPrototype().withId(userId).withUsername("marissa").withEmail("marissa@example.com");
        UaaUser user = new UaaUser(uaaUserPrototype);
        when(userDatabase.retrieveUserById(userId))
                .thenReturn(user);
        when(userDatabase.retrieveUserPrototypeById(userId))
                .thenReturn(uaaUserPrototype);

        ArgumentCaptor<UserAuthenticationData> userAuthenticationDataArgumentCaptor =
                ArgumentCaptor.forClass(UserAuthenticationData.class);

        TimeService timeService = mock(TimeService.class);
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        when(timeService.getCurrentDate()).thenCallRealMethod();
        RefreshTokenCreator refreshTokenCreator = mock(RefreshTokenCreator.class);
        ApprovalService approvalService = mock(ApprovalService.class);
        UaaTokenServices uaaTokenServices = new UaaTokenServices(
                idTokenCreator,
                mock(TokenEndpointBuilder.class),
                mockMultitenantClientServices,
                mock(RevocableTokenProvisioning.class),
                tokenValidationService,
                refreshTokenCreator,
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

        verify(idTokenCreator).create(eq(clientDetails), any(), userAuthenticationDataArgumentCaptor.capture(), any());
        UserAuthenticationData userData = userAuthenticationDataArgumentCaptor.getValue();
        Set<String> expectedRoles = Sets.newHashSet("custom_role");
        assertThat(userData.roles).isEqualTo(expectedRoles);
        assertThat(userData.userAttributes).isEqualTo(userAttributes);
        assertThat(userData.contextClassRef).isEqualTo(acrValue);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void jwt_no_token_is_not_persisted(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(JWT.getStringValue());
        CompositeToken result = tokenServices.persistRevocableToken("id",
                persistToken,
                new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, ""),
                "clientId",
                "userId",
                false,
                false, null);

        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, never()).create(rt.capture(), anyString());
        assertThat(result.getValue()).isEqualTo(persistToken.getValue());
        assertThat(result.getRefreshToken().getValue()).isEqualTo("refresh-token-value");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void opaque_refresh_token_is_persisted(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(OPAQUE.getStringValue());
        CompositeToken result = tokenServices.persistRevocableToken("id",
                persistToken,
                new CompositeExpiringOAuth2RefreshToken("refresh-token-value", expiration, ""),
                "clientId",
                "userId",
                false,
                false, null);

        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, times(1)).createIfNotExists(rt.capture(), anyString());
        assertThat(rt.getAllValues()).hasSize(1);
        assertThat(rt.getAllValues().getFirst().getResponseType()).isEqualTo(RevocableToken.TokenType.REFRESH_TOKEN);
        assertThat(rt.getAllValues().getFirst().getFormat()).isEqualTo(OPAQUE.getStringValue());
        assertThat(rt.getAllValues().getFirst().getValue()).isEqualTo("refresh-token-value");
        assertThat(result.getRefreshToken().getValue()).isNotEqualTo("refresh-token-value");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void isOpaqueTokenRequired(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, TokenConstants.GRANT_TYPE_USER_TOKEN);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        assertThat(tokenServices.isOpaqueTokenRequired(authentication)).isTrue();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void nullRefreshTokenString(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                tokenServices.refreshAccessToken(null, null));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void invalidRefreshToken(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Map<String, String> map = new HashMap<>();
        map.put("grant_type", "refresh_token");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(map, null, null, null, null, false, null, null, null);
        String refreshTokenValue = "dasdasdasdasdas";
        assertThatThrownBy(() -> tokenServices.refreshAccessToken(refreshTokenValue, tokenSupport.requestFactory.createTokenRequest(authorizationRequest, "refresh_token")))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageNotContaining(refreshTokenValue);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void misconfigured_keys_throws_proper_error(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("invalid");
        String jwtValue = JWT.getStringValue();
        assertThatThrownBy(() -> performPasswordGrant(jwtValue))
                .isInstanceOf(InternalAuthenticationServiceException.class)
                .hasMessageContaining("Unable to sign token, misconfigured JWT signing keys");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenForAClient(TestTokenEnhancer enhancer) {

        initDeprecatedUaaTokenServicesTests(enhancer);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken).is(matching(validFor(is(tokenSupport.accessTokenValidity))))
                .is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(zoneId(is(IdentityZoneHolder.get().getId()))));
        assertThat(accessToken.getRefreshToken()).isNull();
        validateExternalAttributes(accessToken);

        assertCommonEventProperties(accessToken, CLIENT_ID, tokenSupport.expectedJson);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenForAnotherIssuer(TestTokenEnhancer enhancer) throws Exception {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken).is(matching(validFor(is(tokenSupport.accessTokenValidity))))
                .is(matching(issuerUri(is("http://uaamaster:8080/uaa/oauth/token"))))
                .is(matching(zoneId(is(IdentityZoneHolder.get().getId()))));
        assertThat(accessToken.getRefreshToken()).isNull();
        validateExternalAttributes(accessToken);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenForInvalidIssuer(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        String subdomain = "test-zone-subdomain";
        IdentityZone identityZone = getIdentityZone(subdomain);
        assertThatThrownBy(() -> identityZone.setConfig(
                JsonUtils.readValue(
                        "{\"issuer\": \"notAnURL\"}",
                        IdentityZoneConfiguration.class
                ))
        )
                .isInstanceOf(JsonUtils.JsonUtilException.class)
                .hasMessageContaining("Invalid issuer format. Must be valid URL.");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refresh_token_is_opaque_when_requested(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        OAuth2AccessToken accessToken = performPasswordGrant(OPAQUE.getStringValue());
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();

        String refreshTokenValue = accessToken.getRefreshToken().getValue();
        assertThat(refreshTokenValue).hasSizeLessThanOrEqualTo(36);
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI))))
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30))));
        TokenRequest refreshTokenRequest = getRefreshTokenRequest();

        //validate both opaque and JWT refresh tokenSupport.tokens
        for (String s : Arrays.asList(refreshTokenValue, tokenSupport.tokens.get(refreshTokenValue).getValue())) {
            OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(s, refreshTokenRequest);
            assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        }
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void using_opaque_parameter_on_refresh_grant(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        OAuth2AccessToken accessToken = performPasswordGrant(OPAQUE.getStringValue());
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        String refreshTokenValue = refreshToken.getValue();

        Map<String, String> parameters = new HashMap<>();
        parameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        TokenRequest refreshTokenRequest = getRefreshTokenRequest(parameters);

        //validate both opaque and JWT refresh tokenSupport.tokens
        for (String s : Arrays.asList(refreshTokenValue, tokenSupport.tokens.get(refreshTokenValue).getValue())) {
            OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(s, refreshTokenRequest);
            assertThat(refreshedAccessToken.getValue()).hasSizeLessThanOrEqualTo(36);
            assertCommonUserAccessTokenProperties(new DefaultOAuth2AccessToken(tokenSupport.tokens.get(refreshedAccessToken).getValue()), CLIENT_ID);
            validateExternalAttributes(refreshedAccessToken);
        }
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createOpaqueAccessTokenForAClient(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken).as("Token is not a composite token").isInstanceOf(CompositeToken.class);
        assertThat(accessToken.getValue()).as("Token value should be equal to or lesser than 36 characters").hasSizeLessThanOrEqualTo(36);
        assertThat(accessToken.getRefreshToken()).isNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenForAClientInAnotherIdentityZone(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken).is(matching(validFor(is(3600))))
                .is(matching(issuerUri(is("http://" + subdomain + ".localhost:8080/uaa/oauth/token"))));
        assertThat(accessToken.getRefreshToken()).isNull();
        validateExternalAttributes(accessToken);

        assertThat(tokenSupport.publisher.getEventCount()).isOne();

        this.assertCommonEventProperties(accessToken, CLIENT_ID, tokenSupport.expectedJson);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenAuthcodeGrant(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        assertThat(castAccessToken.getIdTokenValue()).isNotNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenOnlyForClientWithoutRefreshToken(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID_NO_REFRESH_TOKEN_GRANT, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        validateAccessTokenOnly(accessToken, CLIENT_ID_NO_REFRESH_TOKEN_GRANT);
        assertThat(accessToken.getRefreshToken()).isNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenAuthcodeGrantSwitchedPrimaryKey(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
            when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
            OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

            validateAccessAndRefreshToken(accessToken);
        } finally {
            tokenSupport.tokenPolicy.setActiveKeyId(originalPrimaryKeyId);
        }
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenPasswordGrant(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        validateAccessAndRefreshToken(accessToken);
        tokenServices.loadAuthentication(accessToken.getValue());

        //ensure that we can load without user_name claim
        tokenServices.setExcludedClaims(new HashSet(Arrays.asList(ClaimConstants.AUTHORITIES, ClaimConstants.USER_NAME, ClaimConstants.EMAIL)));
        accessToken = tokenServices.createAccessToken(authentication);
        assertThat(tokenServices.loadAuthentication(accessToken.getValue()).getUserAuthentication()).isNotNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void missing_required_user_groups(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        tokenSupport.defaultClient.addAdditionalInformation(REQUIRED_USER_GROUPS, singletonList("uaa.admin"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        assertThatThrownBy(() -> tokenServices.createAccessToken(authentication))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessage("User does not meet the client's required group criteria.");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void clientSecretAddedTokenValidationStillWorks(TestTokenEnhancer enhancer) {

        initDeprecatedUaaTokenServicesTests(enhancer);

        tokenSupport.defaultClient.setClientSecret(SECRET);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        //normal token validation
        String accessTokenValue = accessToken.getValue();
        tokenServices.loadAuthentication(accessTokenValue);

        //add a 2nd secret
        tokenSupport.defaultClient.setClientSecret(tokenSupport.defaultClient.getClientSecret() + " newsecret");
        tokenServices.loadAuthentication(accessTokenValue);

        //generate a token when we have two secrets
        OAuth2AccessToken accessToken2 = tokenServices.createAccessToken(authentication);

        //remove the 1st secret
        tokenSupport.defaultClient.setClientSecret("newsecret");
        assertThatThrownBy(() -> tokenServices.loadAuthentication(accessTokenValue))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("revocable signature mismatch");

        tokenServices.loadAuthentication(accessToken2.getValue());

        OAuth2AccessToken accessToken3 = tokenServices.createAccessToken(authentication);
        tokenServices.loadAuthentication(accessToken3.getValue());
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createRevocableAccessTokenPasswordGrant(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        OAuth2AccessToken accessToken = performPasswordGrant();

        validateAccessAndRefreshToken(accessToken);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenExternalContext(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        TokenRequest refreshTokenRequest = getRefreshTokenRequest();
        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshTokenRequest);

        validateExternalAttributes(accessToken);
        validateExternalAttributes(refreshedAccessToken);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenRefreshGrant(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        TokenRequest refreshTokenRequest = getRefreshTokenRequest();

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshTokenRequest);

        assertThat(accessToken.getRefreshToken().getValue()).isEqualTo(refreshedAccessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));
        validateExternalAttributes(accessToken);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenRefreshGrantWithAnOldRefreshTokenFormatContainingScopesClaim(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        //Given
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(JWT.getStringValue());
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        String refreshTokenWithOnlyScopeClaimNotGrantedScopeClaim = UaaTokenUtils.constructToken(tokenJwtHeaderMap, claimsWithScopeAndNotGrantedScopeMap, new KeyInfoService(DEFAULT_ISSUER).getKey(kid).getSigner());

        //When
        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(refreshTokenWithOnlyScopeClaimNotGrantedScopeClaim, getRefreshTokenRequest());

        //Then
        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));
        validateExternalAttributes(accessToken);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessToken_usingRefreshGrant_inOtherZone(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);
        useIZMIforAccessToken(tokenServices);
        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
        assertThat(accessToken.getRefreshToken().getValue()).isEqualTo(refreshedAccessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken).is(matching(issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token"))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(3600))));
        validateExternalAttributes(accessToken);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenRefreshGrantAllScopesAutoApproved(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        UaaClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI))))
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30))));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));

        assertThat(accessToken.getRefreshToken().getValue()).isEqualTo(refreshedAccessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));
        assertThat(accessToken.getRefreshToken()).isNotNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenRefreshGrantSomeScopesAutoApprovedDowngradedRequest(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        UaaClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI))))
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30))));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.readScope);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));

        assertThat(accessToken.getRefreshToken().getValue()).isEqualTo(refreshedAccessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(validFor(is(60 * 60 * 12))));
        assertThat(accessToken.getRefreshToken()).isNotNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenRefreshGrantSomeScopesAutoApproved(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        UaaClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
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
                .setScope(tokenSupport.writeScope.getFirst())
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI))))
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30))));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));

        assertThat(accessToken.getRefreshToken().getValue()).isEqualTo(refreshedAccessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(validFor(is(60 * 60 * 12))));
        assertThat(accessToken.getRefreshToken()).isNotNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenRefreshGrantNoScopesAutoApprovedIncompleteApprovals(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        UaaClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
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
                .setScope(tokenSupport.writeScope.getFirst())
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI))))
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30))));
        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));
        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->

                tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token")));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenRefreshGrantAllScopesAutoApprovedButApprovalDenied(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        UaaClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
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
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI))))
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30))));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
        assertThat(refreshedAccessToken).isNotNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenImplicitGrant(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_IMPLICIT);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(validFor(is(60 * 60 * 12))));
        assertThat(accessToken.getRefreshToken()).isNull();

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void create_id_token_with_roles_scope(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Jwt idTokenJwt = getIdToken(singletonList(OPENID));
        assertThat(idTokenJwt.getClaims()).contains("\"amr\":[\"ext\",\"rba\",\"mfa\"]");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void create_id_token_with_amr_claim(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertThat(idTokenJwt.getClaims()).contains("\"amr\":[\"ext\",\"rba\",\"mfa\"]");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void create_id_token_with_acr_claim(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertThat(idTokenJwt.getClaims()).contains("\"" + ClaimConstants.ACR + "\":{\"values\":[\"");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void create_id_token_without_roles_scope(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Jwt idTokenJwt = getIdToken(singletonList(OPENID));
        assertThat(idTokenJwt.getClaims()).doesNotContain("\"roles\"");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void create_id_token_with_profile_scope(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, PROFILE));
        assertThat(idTokenJwt.getClaims()).contains("\"given_name\":\"" + tokenSupport.defaultUser.getGivenName() + "\"");
        assertThat(idTokenJwt.getClaims()).contains("\"family_name\":\"" + tokenSupport.defaultUser.getFamilyName() + "\"");
        assertThat(idTokenJwt.getClaims()).contains("\"phone_number\":\"" + tokenSupport.defaultUser.getPhoneNumber() + "\"");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void create_id_token_without_profile_scope(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Jwt idTokenJwt = getIdToken(singletonList(OPENID));
        assertThat(idTokenJwt.getClaims()).doesNotContain("\"given_name\":")
                .doesNotContain("\"family_name\":")
                .doesNotContain("\"phone_number\":");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void create_id_token_with_last_logon_time_claim(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Jwt idTokenJwt = getIdToken(singletonList(OPENID));
        assertThat(idTokenJwt.getClaims()).contains("\"previous_logon_time\":12365");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessWithNonExistingScopes(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        assertThat(accessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(scopesThatDontExist))))
                .is(matching(validFor(greaterThan(60 * 60 * 12))));
        assertThat(accessToken.getRefreshToken()).isNull();

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(scopesThatDontExist));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessToken_forUser_inanotherzone(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken, CLIENT_ID);
        assertThat(accessToken).is(matching(issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token"))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(3600))));
        assertThat(accessToken.getRefreshToken()).isNotNull();

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token"))))
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(9600))));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenAuthcodeGrantNarrowerScopes(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken).is(matching(scope(is(tokenSupport.requestedAuthScopes))));
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        assertThat(refreshToken).isNotNull()
                .is(matching(OAuth2RefreshTokenMatchers.scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(OAuth2RefreshTokenMatchers.audience(is(tokenSupport.resourceIds))));

        // Second request with reduced scopes
        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.readScope);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken reducedScopeAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(reducedScopeAuthorizationRequest, "refresh_token"));

        // AT should have the new scopes, RT should be the same
        assertThat(reducedScopeAccessToken).is(matching(scope(is(tokenSupport.readScope))));
        assertThat(accessToken.getRefreshToken()).isEqualTo(reducedScopeAccessToken.getRefreshToken());
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenAuthcodeGrantExpandedScopes(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThat(accessToken).is(matching(scope(is(tokenSupport.requestedAuthScopes))));
        assertThat(accessToken.getRefreshToken()).isNotNull()
                .is(matching(OAuth2RefreshTokenMatchers.scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(OAuth2RefreshTokenMatchers.audience(is(tokenSupport.resourceIds))));
        AuthorizationRequest expandedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.expandedScopes);
        expandedScopeAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(expandedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        expandedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);
        assertThatExceptionOfType(InvalidScopeException.class).isThrownBy(() ->
                tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(expandedScopeAuthorizationRequest, "refresh_token")));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void changedExpiryForTokens(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        UaaClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken).is(matching(validFor(is(3600))));
        assertThat(accessToken.getRefreshToken()).isNotNull()
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(36000))));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void userUpdatedAfterRefreshTokenIssued(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
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
        assertThatExceptionOfType(TokenRevokedException.class).isThrownBy(() ->

                tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token")));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refreshTokenExpiry(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());

        UaaClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
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

        assertThatThrownBy(() -> tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token")))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageNotContaining(accessToken.getRefreshToken().getValue());
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refreshTokenAfterApprovalsRevoked(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        for (Approval approval : tokenSupport.approvalStore.getApprovals(tokenSupport.userId, CLIENT_ID, IdentityZoneHolder.get().getId())) {
            tokenSupport.approvalStore.revokeApproval(approval, IdentityZoneHolder.get().getId());
        }
        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->

                tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token")));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refreshTokenAfterApprovalsExpired(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
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
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->

                tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token")));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refreshTokenAfterApprovalsDenied(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.DENIED), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
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
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->

                tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token")));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refreshTokenAfterApprovalsMissing(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.readScope.getFirst())
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
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->

                tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token")));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refreshTokenAfterApprovalsMissing2(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->

                tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token")));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void testReadAccessToken(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        readAccessToken(emptySet());
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void readAccessTokenNoPII(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        readAccessToken(new HashSet<>(Arrays.asList(ClaimConstants.EMAIL, ClaimConstants.USER_NAME)));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void readAccessTokenWhenGivenRefreshTokenShouldThrowException(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt1.getTime())
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(updatedAt1.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
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
        assertThatThrownBy(() ->
                tokenServices.readAccessToken(accessToken.getRefreshToken().getValue()))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("The token does not bear a \"scope\" claim.");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void readAccessTokenForDeletedUserId(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        this.tokenSupport.userDatabase.clear();
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                assertThat(tokenServices.readAccessToken(accessToken.getValue())).isEqualTo(accessToken));
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void loadAuthenticationForAUser(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertThat(loadedAuthentication.getAuthorities()).isEqualTo(USER_AUTHORITIES);
        assertThat(loadedAuthentication.getName()).isEqualTo(tokenSupport.username);
        UaaPrincipal uaaPrincipal = (UaaPrincipal) tokenSupport.defaultUserAuthentication.getPrincipal();
        assertThat(loadedAuthentication.getPrincipal()).isEqualTo(uaaPrincipal);
        assertThat(loadedAuthentication.getDetails()).isNull();

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertThat(userAuth.getName()).isEqualTo(tokenSupport.username);
        assertThat(userAuth.getPrincipal()).isEqualTo(uaaPrincipal);
        assertThat(userAuth.isAuthenticated()).isTrue();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void load_Opaque_AuthenticationForAUser(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        tokenSupport.defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        azParameters.put(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThat(accessToken).as("Token should be composite token").isInstanceOf(CompositeToken.class);
        CompositeToken composite = (CompositeToken) accessToken;
        assertThat(composite.getIdTokenValue()).hasSizeGreaterThan(36);
        assertThat(accessToken.getValue()).hasSizeLessThanOrEqualTo(36);
        assertThat(accessToken.getRefreshToken().getValue()).hasSizeLessThanOrEqualTo(36);

        String accessTokenValue = tokenProvisioning.retrieve(composite.getValue(), IdentityZoneHolder.get().getId()).getValue();
        Map<String, Object> accessTokenClaims = tokenSupport.tokenValidationService.validateToken(accessTokenValue, true).getClaims();
        assertThat((Boolean) accessTokenClaims.get(ClaimConstants.REVOCABLE)).isTrue();

        String refreshTokenValue = tokenProvisioning.retrieve(composite.getRefreshToken().getValue(), IdentityZoneHolder.get().getId()).getValue();
        Map<String, Object> refreshTokenClaims = tokenSupport.tokenValidationService.validateToken(refreshTokenValue, false).getClaims();
        assertThat((Boolean) refreshTokenClaims.get(ClaimConstants.REVOCABLE)).isTrue();

        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertThat(loadedAuthentication.getAuthorities()).isEqualTo(USER_AUTHORITIES);
        assertThat(loadedAuthentication.getName()).isEqualTo(tokenSupport.username);
        UaaPrincipal uaaPrincipal = (UaaPrincipal) tokenSupport.defaultUserAuthentication.getPrincipal();
        assertThat(loadedAuthentication.getPrincipal()).isEqualTo(uaaPrincipal);
        assertThat(loadedAuthentication.getDetails()).isNull();

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertThat(userAuth.getName()).isEqualTo(tokenSupport.username);
        assertThat(userAuth.getPrincipal()).isEqualTo(uaaPrincipal);
        assertThat(userAuth.isAuthenticated()).isTrue();

        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "refresh_token");
        params.put("client_id", CLIENT_ID);
        params.put("token_format", OPAQUE.getStringValue());
        OAuth2AccessToken newAccessToken = tokenServices.refreshAccessToken(composite.getRefreshToken().getValue(), new TokenRequest(params, CLIENT_ID, Collections.emptySet(), "refresh_token"));
        assertThat(newAccessToken.getValue()).hasSizeLessThanOrEqualTo(36);
        assertThat(newAccessToken.getRefreshToken().getValue()).hasSizeLessThanOrEqualTo(36);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void loadAuthentication_when_given_an_opaque_refreshToken_should_throw_exception(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        assertThatThrownBy(() -> tokenServices.loadAuthentication(refreshTokenValue))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("The token does not bear a \"scope\" claim.");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void loadAuthentication_when_given_an_refresh_jwt_should_throw_exception(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
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
        JwtTokenSignedByThisUAA refreshToken = tokenSupport.tokenValidationService.validateToken(compositeToken.getRefreshToken().getValue(), false);
        String refreshTokenValue = tokenProvisioning.retrieve(refreshToken.getClaims().get("jti").toString(), IdentityZoneHolder.get().getId()).getValue();
        assertThatThrownBy(() -> tokenServices.loadAuthentication(refreshTokenValue))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("The token does not bear a \"scope\" claim.");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void loadAuthenticationForAClient(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertThat(loadedAuthentication.getAuthorities()).as("Client authorities match.").containsExactlyInAnyOrderElementsOf(AuthorityUtils.commaSeparatedStringToAuthorityList(CLIENT_AUTHORITIES));
        assertThat(loadedAuthentication.getName()).isEqualTo(CLIENT_ID);
        assertThat(loadedAuthentication.getPrincipal()).isEqualTo(CLIENT_ID);
        assertThat(loadedAuthentication.getDetails()).isNull();

        assertThat(loadedAuthentication.getUserAuthentication()).isNull();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void loadAuthenticationWithAnExpiredToken(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        UaaClientDetails shortExpiryClient = tokenSupport.defaultClient;
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod().thenReturn(2001L);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        String accessTokenValue = accessToken.getValue();
        assertThatThrownBy(() -> tokenServices.loadAuthentication(accessTokenValue))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageNotContaining(accessTokenValue);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createAccessTokenAuthcodeGrantAdditionalAuthorizationAttributes(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        azParameters.put("authorities", "{\"az_attr\":{\"external_group\":\"domain\\\\group1\", \"external_id\":\"abcd1234\"}}");
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken token = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(token, CLIENT_ID);
        assertThat(token).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));

        OAuth2RefreshToken refreshToken = token.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI))));
        //assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.validFor(greaterThan(60 * 60 * 24 * 30))))

        this.assertCommonEventProperties(token, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));

        Map<String, String> azMap = new LinkedHashMap<>();
        azMap.put("external_group", "domain\\group1");
        azMap.put("external_id", "abcd1234");
        assertThat(token.getAdditionalInformation()).containsEntry("az_attr", azMap);
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void wrongClientDoesNotLeakToken(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        OAuth2AccessToken accessToken = getOAuth2AccessToken();
        TokenRequest refreshTokenRequest = getRefreshTokenRequest();
        refreshTokenRequest.setClientId("invalidClientForToken");
        assertThatThrownBy(() -> tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), refreshTokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageStartingWith("Wrong client for this refresh token")
                .hasMessageNotContaining(accessToken.getRefreshToken().getValue());
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void createRefreshToken_JwtDoesNotContainScopeClaim(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(JWT.getStringValue());
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        Map<String, String> authzParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        authzParameters.put(GRANT_TYPE, GRANT_TYPE_PASSWORD);
        authzParameters.put(REQUEST_TOKEN_FORMAT, JWT.toString());
        authorizationRequest.setRequestParameters(authzParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        String refreshTokenString = accessToken.getRefreshToken().getValue();
        assertThat(refreshTokenString).isNotNull();

        Claims refreshTokenClaims = UaaTokenUtils.getClaimsFromTokenString(refreshTokenString);
        assertThat(refreshTokenClaims).isNotNull();
        assertThat(refreshTokenClaims.getScope()).isNull();
        // the matcher below can't match list against set
        assertThat(refreshTokenClaims.getGrantedScopes()).containsExactlyInAnyOrderElementsOf(accessToken.getScope());
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void refreshAccessToken_withAccessToken(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        assertThatThrownBy(() -> tokenServices.refreshAccessToken(getOAuth2AccessToken().getValue(), getRefreshTokenRequest()))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Invalid refresh token.");
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void isRevocableTrueIfOpaque(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Claims claims = new Claims();
        claims.setRevocable(false);

        boolean revocable = tokenServices.isRevocable(new Claims(), true);
        assertThat(revocable).isTrue();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void isRevocableTrueIfRevocableAndNotOpaque(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Claims claims = new Claims();
        claims.setRevocable(true);

        boolean revocable = tokenServices.isRevocable(new Claims(), true);
        assertThat(revocable).isTrue();
    }

    @MethodSource("data")
    @ParameterizedTest(name = "{index}: {0}")
    void isRevocableFalseIfRevocableAndNotOpaque(TestTokenEnhancer enhancer) {
        initDeprecatedUaaTokenServicesTests(enhancer);
        Claims claims = new Claims();
        claims.setRevocable(false);

        boolean revocable = tokenServices.isRevocable(new Claims(), false);

        assertThat(revocable).isFalse();
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
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        String accessTokenValue = accessToken.getValue();
        assertThat(tokenServices.readAccessToken(accessTokenValue)).isEqualTo(accessToken);

        tokenSupport.approvalStore.revokeApproval(approval, IdentityZoneHolder.get().getId());
        assertThatThrownBy(() -> tokenServices.readAccessToken(accessTokenValue))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("some requested scopes are not approved");
    }

    private Jwt getIdToken(List<String> scopes) {
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
        return tokenSupport.getIdToken(scopes);
    }

    private String buildJsonString(List<String> list) {
        StringBuilder buf = new StringBuilder("[");
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
        when(tokenSupport.timeService.getCurrentTimeMillis()).thenCallRealMethod();
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
        assertThat(accessToken).is(matching(issuerUri(is(ISSUER_URI))))
                .is(matching(scope(is(tokenSupport.requestedAuthScopes))))
                .is(matching(validFor(is(60 * 60 * 12))));
        validateExternalAttributes(accessToken);
    }

    private void validateAccessAndRefreshToken(OAuth2AccessToken accessToken) {
        validateAccessTokenOnly(accessToken, CLIENT_ID);

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken).is(matching(OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI))))
                .is(matching(OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30))));

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

            assertThat(claims).containsKey("ext_attr")
                    .containsKey("ex_prop");
            assertThat(((Map) claims.get("ext_attr"))).containsEntry("purpose", "test");
            assertThat(((Map) claims.get("ex_prop"))).containsEntry("country", "nz");

            assertThat((List<String>) claims.get("ex_groups")).containsExactlyInAnyOrder("admin", "editor");
        } else {
            assertThat(extendedAttributes).as("External attributes should not exist").isNull();
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
                .setScope(tokenSupport.readScope.getFirst())
                .setExpiresAt(expiresAt.getTime())
                .setStatus(ApprovalStatus.APPROVED)
                .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());
        tokenSupport.approvalStore.addApproval(new Approval()
                .setUserId(tokenSupport.userId)
                .setClientId(CLIENT_ID)
                .setScope(tokenSupport.writeScope.getFirst())
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

    private UaaClientDetails cloneClient(ClientDetails client) {
        return new UaaClientDetails(client);
    }

    @SuppressWarnings("unchecked")
    private void assertCommonClientAccessTokenProperties(OAuth2AccessToken accessToken) {
        assertThat(accessToken)
                .is(matching(clientId(is(CLIENT_ID))))
                .is(matching(userId(nullValue())))
                .is(matching(subject(is(CLIENT_ID))))
                .is(matching(username(is(nullValue()))))
                .is(matching(cid(is(CLIENT_ID))))
                .is(matching(scope(is(tokenSupport.clientScopes))))
                .is(matching(audience(containsInAnyOrder(tokenSupport.resourceIds.toArray(new String[]{})))))
                .is(matching(jwtId(not(emptyString()))))
                .is(matching(issuedAt(is(greaterThan(0)))))
                .is(matching(expiry(is(greaterThan(0)))));
    }

    @SuppressWarnings({"unused", "unchecked"})
    private void assertCommonUserAccessTokenProperties(OAuth2AccessToken accessToken, String clientId) {
        assertThat(accessToken)
                .is(matching(username(is(tokenSupport.username))))
                .is(matching(clientId(is(clientId))))
                .is(matching(subject(is(tokenSupport.userId))))
                .is(matching(audience(containsInAnyOrder(tokenSupport.resourceIds.toArray(new String[]{})))))
                .is(matching(origin(is(OriginKeys.UAA))))
                .is(matching(revocationSignature(not(nullValue()))))
                .is(matching(cid(is(clientId))))
                .is(matching(userId(is(tokenSupport.userId))))
                .is(matching(email(is(tokenSupport.email))))
                .is(matching(jwtId(not(emptyString()))))
                .is(matching(issuedAt(is(greaterThan(0)))))
                .is(matching(expiry(is(greaterThan(0)))));
    }

    @SuppressWarnings("unchecked")
    private void assertCommonUserRefreshTokenProperties(OAuth2RefreshToken refreshToken) {
        assertThat(refreshToken)
                .is(matching(OAuth2RefreshTokenMatchers.username(is(tokenSupport.username))))
                .is(matching(OAuth2RefreshTokenMatchers.clientId(is(CLIENT_ID))))
                .is(matching(OAuth2RefreshTokenMatchers.subject(not(nullValue()))))
                .is(matching(OAuth2RefreshTokenMatchers.audience(containsInAnyOrder(tokenSupport.resourceIds.toArray(new String[]{})))))
                .is(matching(OAuth2RefreshTokenMatchers.origin(is(OriginKeys.UAA))))
                .is(matching(OAuth2RefreshTokenMatchers.revocationSignature(is(not(nullValue())))))
                .is(matching(OAuth2RefreshTokenMatchers.jwtId(not(emptyString()))))
                .is(matching(OAuth2RefreshTokenMatchers.issuedAt(is(greaterThan(0)))))
                .is(matching(OAuth2RefreshTokenMatchers.expiry(is(greaterThan(0)))));
    }

    private void assertCommonEventProperties(OAuth2AccessToken accessToken, String expectedPrincipalId, String expectedData) {
        assertThat(tokenSupport.publisher.getEventCount()).isOne();

        TokenIssuedEvent event = tokenSupport.publisher.getLatestEvent();
        assertThat(event.getSource()).isEqualTo(accessToken);
        assertThat(event.getAuthentication()).isEqualTo(tokenSupport.mockAuthentication);
        AuditEvent auditEvent = event.getAuditEvent();
        assertThat(auditEvent.getPrincipalId()).isEqualTo(expectedPrincipalId);
        assertThat(auditEvent.getData()).isEqualTo(expectedData);
        assertThat(auditEvent.getType()).isEqualTo(AuditEventType.TokenIssuedEvent);
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
