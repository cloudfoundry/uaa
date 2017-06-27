/*******************************************************************************
*     Cloud Foundry
*     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
*
*     This product is licensed to you under the Apache License, Version 2.0 (the "License").
*     You may not use this product except in compliance with the License.
*
*     This product includes a number of subcomponents with
*     separate copyright notices and license terms. Your use of these
*     subcomponents is subject to the terms and conditions of the
*     subcomponent's license, as noted in the LICENSE file.
*******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.collections.map.HashedMap;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.AbstractOAuth2AccessTokenMatchers;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2RefreshTokenMatchers;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import static java.util.Collections.EMPTY_SET;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singleton;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_AUTHORITIES;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_ID_NO_REFRESH_TOKEN_GRANT;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.ISSUER_URI;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.OPENID;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.PROFILE;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.UaaTokenServices.UAA_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
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
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.AllOf.allOf;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.hamcrest.number.OrderingComparison.lessThanOrEqualTo;
import static org.hamcrest.text.IsEmptyString.isEmptyString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(Parameterized.class)
public class UaaTokenServicesTests {


    private TestTokenEnhancer tokenEnhancer;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    private Set<String> thousandScopes;
    private CompositeAccessToken persistToken;
    private Date expiration;

    private TokenTestSupport tokenSupport;
    private RevocableTokenProvisioning tokenProvisioning;

    private Calendar expiresAt = Calendar.getInstance();
    private Calendar updatedAt = Calendar.getInstance();


    public UaaTokenServicesTests(TestTokenEnhancer enhancer, String testname) {
        this.tokenEnhancer = enhancer;
    }

    @Parameterized.Parameters(name = "{index}: testname[{1}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {{null, "old behavior"}, {new TestTokenEnhancer(),"using enhancer"}});
    }

    private UaaTokenServices tokenServices;

    @Before
    public void setUp() throws Exception {
        tokenSupport = new TokenTestSupport(tokenEnhancer);

        thousandScopes = new HashSet<>();
        for (int i=0; i<1000; i++) {
            thousandScopes.add(String.valueOf(i));
        }
        persistToken = new CompositeAccessToken("token-value");
        expiration = new Date(System.currentTimeMillis() + 10000);
        persistToken.setScope(thousandScopes);
        persistToken.setExpiration(expiration);

        tokenServices = tokenSupport.getUaaTokenServices();
        tokenProvisioning = tokenSupport.getTokenProvisioning();

    }

    @After
    public void teardown() {
        AbstractOAuth2AccessTokenMatchers.revocableTokens.remove();
        IdentityZoneHolder.clear();
        tokenSupport.clear();
    }

    @Test
    public void test_opaque_tokens_are_persisted() throws Exception {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(false);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(JWT.getStringValue());
        CompositeAccessToken result = tokenServices.persistRevocableToken("id",
                                                                          "rid",
                                                                          persistToken,
                                                                          new DefaultExpiringOAuth2RefreshToken("refresh-token-value", expiration),
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
        assertEquals(RevocableToken.TokenFormat.OPAQUE.name(), rt.getAllValues().get(0).getFormat());
        assertEquals("id", result.getValue());
        assertEquals(RevocableToken.TokenType.REFRESH_TOKEN, rt.getAllValues().get(1).getResponseType());
        assertEquals(RevocableToken.TokenFormat.OPAQUE.name(), rt.getAllValues().get(1).getFormat());
        assertEquals("rid", result.getRefreshToken().getValue());
    }

    @Test
    public void test_refresh_tokens_are_uniquely_persisted() {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenUnique(true);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        tokenServices.persistRevocableToken("id",
                "rid",
                persistToken,
                new DefaultExpiringOAuth2RefreshToken("refresh-token-value", expiration),
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
                "rid",
                persistToken,
                new DefaultExpiringOAuth2RefreshToken("refresh-token-value", expiration),
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
    public void test_jwt_no_token_is_not_persisted() throws Exception {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(JWT.getStringValue());
        CompositeAccessToken result = tokenServices.persistRevocableToken("id",
                                                                          "rid",
                                                                          persistToken,
                                                                          new DefaultExpiringOAuth2RefreshToken("refresh-token-value", expiration),
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
    public void test_opaque_refresh_token_is_persisted() throws Exception {
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        CompositeAccessToken result = tokenServices.persistRevocableToken("id",
                                                                          "rid",
                                                                          persistToken,
                                                                          new DefaultExpiringOAuth2RefreshToken("refresh-token-value", expiration),
                                                                          "clientId",
                                                                          "userId",
                                                                          false,
                                                                          false);

        ArgumentCaptor<RevocableToken> rt = ArgumentCaptor.forClass(RevocableToken.class);
        verify(tokenProvisioning, times(1)).create(rt.capture(), anyString());
        assertNotNull(rt.getAllValues());
        assertEquals(1, rt.getAllValues().size());
        assertEquals(RevocableToken.TokenType.REFRESH_TOKEN, rt.getAllValues().get(0).getResponseType());
        assertEquals(RevocableToken.TokenFormat.OPAQUE.name(), rt.getAllValues().get(0).getFormat());
        assertEquals("refresh-token-value", rt.getAllValues().get(0).getValue());
        assertNotEquals("refresh-token-value", result.getRefreshToken().getValue());
    }

    @Test
    public void null_issuer_should_fail() throws URISyntaxException {
        tokenServices = new UaaTokenServices();
        tokenServices.setClientDetailsService(mock(ClientServicesExtension.class));
        try {
            tokenServices.afterPropertiesSet();
            fail();
        } catch (IllegalArgumentException x) {
            assertTrue(x.getMessage().contains("issuer must be set"));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void do_not_allow_set_of_null_issuer() throws URISyntaxException {
        tokenServices.setIssuer(null);
    }

    @Test(expected = URISyntaxException.class)
    public void do_not_allow_set_of_non_url_issuer() throws URISyntaxException {
        tokenServices.setIssuer("some bla bla bla");
    }

    @Test(expected = IllegalArgumentException.class)
    public void getTokenEndpoint_Fails_If_Issuer_Is_Wrong() throws Exception {
        Field field = UaaTokenServices.class.getDeclaredField("issuer");
        field.setAccessible(true);
        ReflectionUtils.setField(field, tokenServices, "adasdas");
        tokenServices.getTokenEndpoint();
    }


    @Test
    public void is_opaque_token_required() {
        tokenSupport.defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResponseTypes(new HashSet(Arrays.asList(CompositeAccessToken.ID_TOKEN, "token")));
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, TokenConstants.GRANT_TYPE_USER_TOKEN);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        assertTrue(tokenServices.opaqueTokenRequired(authentication));
    }

    @Test(expected = InvalidTokenException.class)
    public void testNullRefreshTokenString() {
        tokenServices.refreshAccessToken(null, null);
    }

    @Test(expected = InvalidGrantException.class)
    public void testInvalidGrantType() {
        AuthorizationRequest ar = mock(AuthorizationRequest.class);
        tokenServices.refreshAccessToken("", tokenSupport.requestFactory.createTokenRequest(ar,"dsdada"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testInvalidRefreshToken() {
        Map<String,String> map = new HashMap<>();
        map.put("grant_type", "refresh_token");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(map,null,null,null,null,null,false,null,null,null);
        tokenServices.refreshAccessToken("dasdasdasdasdas", tokenSupport.requestFactory.createTokenRequest(authorizationRequest, "refresh_token"));
    }

    @Test
    public void misconfigured_keys_throws_proper_error() {
        expectedEx.expect(InternalAuthenticationServiceException.class);
        expectedEx.expectMessage("Unable to sign token, misconfigured JWT signing keys");
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("invalid");
        performPasswordGrant(JWT.getStringValue());
    }


    @Test
    public void testCreateAccessTokenForAClient() {

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
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
    public void test_refresh_token_is_opaque_when_requested() {
        OAuth2AccessToken accessToken = performPasswordGrant(TokenConstants.TokenFormat.OPAQUE.getStringValue());
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
        OAuth2AccessToken accessToken = performPasswordGrant(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        String refreshTokenValue = refreshToken.getValue();

        Map<String,String> parameters = new HashMap<>();
        parameters.put(REQUEST_TOKEN_FORMAT, OPAQUE);
        TokenRequest refreshTokenRequest = getRefreshTokenRequest(parameters);

        //validate both opaque and JWT refresh tokenSupport.tokens
        for (String s : Arrays.asList(refreshTokenValue, tokenSupport.tokens.get(refreshTokenValue).getValue())) {
            OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(s, refreshTokenRequest);
            assertThat("Token value should be equal to or lesser than 36 characters", refreshedAccessToken.getValue().length(), lessThanOrEqualTo(36));
            assertCommonUserAccessTokenProperties(new DefaultOAuth2AccessToken(tokenSupport.tokens.get(refreshedAccessToken).getValue()), CLIENT_ID);
        }
    }

    protected OAuth2AccessToken performPasswordGrant() {
        return performPasswordGrant(JWT.getStringValue());
    }
    protected OAuth2AccessToken performPasswordGrant(String tokenFormat) {
        AuthorizationRequest authorizationRequest =  new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
        azParameters.put(REQUEST_TOKEN_FORMAT, tokenFormat);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        return tokenServices.createAccessToken(authentication);
    }

    @Test
    public void testCreateOpaqueAccessTokenForAClient() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE);
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertTrue("Token is not a composite token", accessToken instanceof CompositeAccessToken);
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
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken, validFor(is(3600)));
        assertThat(accessToken, issuerUri(is("http://"+subdomain+".localhost:8080/uaa/oauth/token")));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));
        validateExternalAttributes(accessToken);

        Assert.assertEquals(1, tokenSupport.publisher.getEventCount());

        this.assertCommonEventProperties(accessToken, CLIENT_ID, tokenSupport.expectedJson);
    }

    private IdentityZone getIdentityZone(String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(subdomain);
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        validateAccessAndRefreshToken(accessToken);
    }

    @Test
    public void testCreateAccessTokenOnlyForClientWithoutRefreshToken() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID_NO_REFRESH_TOKEN_GRANT,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

            AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
            authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
            Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
            azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
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

        tokenSupport.defaultClient.addAdditionalInformation(REQUIRED_USER_GROUPS, Arrays.asList("uaa.admin"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        expectedEx.expect(InvalidTokenException.class);
        expectedEx.expectMessage("User does not meet the client's required group criteria.");
        tokenServices.createAccessToken(authentication);
    }



    @Test
    public void testClientSecret_Added_Token_Validation_Still_Works() {

        tokenSupport.defaultClient.setClientSecret(SECRET);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        //normal token validation
        tokenServices.loadAuthentication(accessToken.getValue());

        //add a 2nd secret
        tokenSupport.defaultClient.setClientSecret(tokenSupport.defaultClient.getClientSecret()+" newsecret");
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

    private void validateAccessTokenOnly(OAuth2AccessToken accessToken, String clientId) {
        this.assertCommonUserAccessTokenProperties(accessToken, clientId);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        validateExternalAttributes(accessToken);
    }

    protected void validateAccessAndRefreshToken(OAuth2AccessToken accessToken) {
        validateAccessTokenOnly(accessToken, CLIENT_ID);

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        this.assertCommonUserRefreshTokenProperties(refreshToken);
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

        this.assertCommonEventProperties(accessToken, tokenSupport.userId, buildJsonString(tokenSupport.requestedAuthScopes));
    }

    protected void validateExternalAttributes(OAuth2AccessToken accessToken) {
        Map<String, String> extendedAttributes = (Map<String, String>) accessToken.getAdditionalInformation().get(ClaimConstants.EXTERNAL_ATTR);
        if (tokenEnhancer!=null) {
            Assert.assertEquals("test", extendedAttributes.get("purpose"));
        } else {
            assertNull("External attributes should not exist", extendedAttributes);
        }
    }

    @Test
    public void testCreateAccessTokenRefreshGrant() throws InterruptedException {
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

    protected TokenRequest getRefreshTokenRequest() {
        return getRefreshTokenRequest(emptyMap());
    }
    protected TokenRequest getRefreshTokenRequest(Map<String, String> requestParameters) {
        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        refreshAuthorizationRequest.setRequestParameters(requestParameters);
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);
        return tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token");
    }

    @Test
    public void createAccessToken_usingRefreshGrant_inOtherZone() throws Exception {
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

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
        assertThat(refreshedAccessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(3600)));
        validateExternalAttributes(accessToken);
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        return tokenServices.createAccessToken(authentication);
    }

    @Test
    public void testCreateAccessTokenRefreshGrantAllScopesAutoApproved() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        tokenSupport.clientDetailsService.setClientDetailsStore(
            IdentityZoneHolder.get().getId(),
            Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        // NO APPROVALS REQUIRED

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantSomeScopesAutoApprovedDowngradedRequest() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        tokenSupport.clientDetailsService.setClientDetailsStore(
            IdentityZoneHolder.get().getId(),
            Collections.singletonMap(CLIENT_ID, clientDetails)
        );

        // NO APPROVALS REQUIRED

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.readScope);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
     }

    @Test
    public void testCreateAccessTokenRefreshGrantSomeScopesAutoApproved() throws InterruptedException {
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken, CLIENT_ID);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test(expected = InvalidTokenException.class)
    public void testCreateAccessTokenRefreshGrantNoScopesAutoApprovedIncompleteApprovals() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(Arrays.asList());
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantAllScopesAutoApprovedButApprovalDenied() throws InterruptedException {
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
        assertNotNull(refreshedAccessToken);
    }

    @Test
    public void refreshTokenNotCreatedIfGrantTypeRestricted() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), tokenSupport.defaultUserAuthentication);
        tokenServices.setRestrictRefreshGrant(true);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken.getRefreshToken(), is(nullValue()));
    }

    @Test
    public void testCreateAccessTokenImplicitGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, IMPLICIT);
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
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertTrue(idTokenJwt.getClaims().contains("\"amr\":[\"ext\",\"rba\",\"mfa\"]"));
    }

    @Test
    public void create_id_token_with_amr_claim() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertTrue(idTokenJwt.getClaims().contains("\"amr\":[\"ext\",\"rba\",\"mfa\"]"));
    }

    @Test
    public void create_id_token_with_acr_claim() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertTrue(idTokenJwt.getClaims().contains("\"" + ClaimConstants.ACR + "\":{\"values\":[\""));
    }

    @Test
    public void create_id_token_without_roles_scope() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertFalse(idTokenJwt.getClaims().contains("\"roles\""));
    }

    @Test
    public void create_id_token_with_profile_scope() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, PROFILE));
        assertTrue(idTokenJwt.getClaims().contains("\"given_name\":\"" + tokenSupport.defaultUser.getGivenName() + "\""));
        assertTrue(idTokenJwt.getClaims().contains("\"family_name\":\"" + tokenSupport.defaultUser.getFamilyName() + "\""));
        assertTrue(idTokenJwt.getClaims().contains("\"phone_number\":\"" + tokenSupport.defaultUser.getPhoneNumber() + "\""));
    }

    @Test
    public void create_id_token_without_profile_scope() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertFalse(idTokenJwt.getClaims().contains("\"given_name\":"));
        assertFalse(idTokenJwt.getClaims().contains("\"family_name\":"));
        assertFalse(idTokenJwt.getClaims().contains("\"phone_number\":"));
    }

    @Test
    public void create_id_token_with_last_logon_time_claim() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertTrue(idTokenJwt.getClaims().contains("\"previous_logon_time\":12365"));
    }

    private Jwt getIdToken(List<String> scopes) {
        return tokenSupport.getIdToken(scopes);
    }

    @Test
    public void testCreateAccessWithNonExistingScopes() {
        List<String> scopesThatDontExist = Arrays.asList("scope1","scope2");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, scopesThatDontExist);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, IMPLICIT);
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
        tokenSupport.copyClients(IdentityZone.getUaa().getId(), identityZone.getId());
        IdentityZoneHolder.set(identityZone);



        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
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
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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
        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.readScope);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication reducedScopeAuthentication = new OAuth2Authentication(reducedScopeAuthorizationRequest.createOAuth2Request(),userAuthentication);
        OAuth2AccessToken reducedScopeAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(reducedScopeAuthorizationRequest,"refresh_token"));

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
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.scope(is(tokenSupport.requestedAuthScopes)));
        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.audience(is(tokenSupport.resourceIds)));

        // Second request with expanded scopes
        AuthorizationRequest expandedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.expandedScopes);
        expandedScopeAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(expandedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        expandedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication expandedScopeAuthentication = new OAuth2Authentication(expandedScopeAuthorizationRequest.createOAuth2Request(),userAuthentication);
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsRevoked() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

        for(Approval approval : tokenSupport.approvalStore.getApprovals(tokenSupport.userId, CLIENT_ID, IdentityZoneHolder.get().getId())) {
            tokenSupport.approvalStore.revokeApproval(approval, IdentityZoneHolder.get().getId());
        }

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
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

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsMissing2() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void refreshAccessTokenWithGrantTypeRestricted() {
        expectedEx.expect(InsufficientScopeException.class);
        expectedEx.expectMessage("Expected scope "+ UAA_REFRESH_TOKEN+" is missing");

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), tokenSupport.defaultUserAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.readScope);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.setRestrictRefreshGrant(true);
        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(reducedScopeAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void refreshAccessTokenWithGrantTypeRestricted_butRefreshScopePresent() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, Arrays.asList(UAA_REFRESH_TOKEN));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), tokenSupport.defaultUserAuthentication);
        tokenServices.setRestrictRefreshGrant(true);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID, null);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        expiresAt.add(Calendar.MILLISECOND, 300000);
        updatedAt.add(Calendar.MILLISECOND, -1000);
        tokenSupport.approvalStore.addApproval(new Approval()
            .setUserId(tokenSupport.userId)
            .setClientId(CLIENT_ID)
            .setScope(UAA_REFRESH_TOKEN)
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()), IdentityZoneHolder.get().getId());

        tokenServices.setRestrictRefreshGrant(true);
        OAuth2AccessToken refresh_token = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), tokenSupport.requestFactory.createTokenRequest(reducedScopeAuthorizationRequest, "refresh_token"));
        assertNotNull(refresh_token);
    }

    @Test
    public void testReadAccessToken() {
        readAccessToken(EMPTY_SET);
    }

    @Test
    public void testReadAccessToken_No_PII() {
        readAccessToken(new HashSet<>(Arrays.asList(ClaimConstants.EMAIL, ClaimConstants.USER_NAME)));
    }

    public void readAccessToken(Set<String> excludedClaims) {
        tokenServices.setExcludedClaims(excludedClaims);
        AuthorizationRequest authorizationRequest =new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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

    @Test(expected = InvalidTokenException.class)
    public void testReadAccessTokenForDeletedUserId() {
        AuthorizationRequest authorizationRequest =new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
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
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertEquals(USER_AUTHORITIES, loadedAuthentication.getAuthorities());
        assertEquals(tokenSupport.username, loadedAuthentication.getName());
        UaaPrincipal uaaPrincipal = (UaaPrincipal)tokenSupport.defaultUserAuthentication.getPrincipal();
        assertEquals(uaaPrincipal, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertEquals(tokenSupport.username, userAuth.getName());
        assertEquals(uaaPrincipal, userAuth.getPrincipal());
        assertTrue(userAuth.isAuthenticated());
    }

    @Test
    public void validate_token_happy_path() throws Exception {
        test_validateToken_method(ignore -> {});
    }

    @Test
    public void validate_token_user_gone() throws Exception {
        expectedEx.expect(InvalidTokenException.class);
        expectedEx.expectMessage("Token bears a non-existent user ID: " + tokenSupport.userId);
        test_validateToken_method(ignore -> tokenSupport.userDatabase.clear());
    }

    @Test
    public void validate_token_client_gone() throws Exception {
        expectedEx.expect(InvalidTokenException.class);
        expectedEx.expectMessage("Invalid client ID "+tokenSupport.defaultClient.getClientId());
        test_validateToken_method(ignore -> tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), emptyMap()));
    }

    @Test
    public void opaque_tokens_validate_signature() throws Exception {
        expectedEx.expect(InvalidTokenException.class);
        expectedEx.expectMessage("Invalid key ID: testKey");

        Consumer<Void> setup = (ignore) -> {
            Map < String, String > keys = new HashMap<>();
            keys.put("otherKey", "unc0uf98gv89egh4v98749978hv");
            tokenSupport.tokenPolicy.setKeys(keys);
            tokenSupport.tokenPolicy.setActiveKeyId("otherKey");
            IdentityZoneHolder.get().getConfig().setTokenPolicy(tokenSupport.tokenPolicy);
        };

        test_validateToken_method(setup);
    }
    public void test_validateToken_method(Consumer<Void> setup) throws Exception {
        tokenSupport.defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResponseTypes(new HashSet(Arrays.asList(CompositeAccessToken.ID_TOKEN, "token")));
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        azParameters.put(REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertNotNull(accessToken);
        assertTrue("Token should be composite token", accessToken instanceof CompositeAccessToken);
        CompositeAccessToken composite = (CompositeAccessToken)accessToken;
        assertThat("id_token should be JWT, thus longer than 36 characters", composite.getIdTokenValue().length(), greaterThan(36));
        assertThat("Opaque access token must be shorter than 37 characters", accessToken.getValue().length(), lessThanOrEqualTo(36));
        assertThat("Opaque refresh token must be shorter than 37 characters", accessToken.getRefreshToken().getValue().length(), lessThanOrEqualTo(36));

        setup.accept(null);
        tokenServices.validateToken(accessToken.getValue());
    }

    @Test
    public void testLoad_Opaque_AuthenticationForAUser() {
        tokenSupport.defaultClient.setAutoApproveScopes(singleton("true"));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResponseTypes(new HashSet(Arrays.asList(CompositeAccessToken.ID_TOKEN, "token")));
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        azParameters.put(REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertNotNull(accessToken);
        assertTrue("Token should be composite token", accessToken instanceof CompositeAccessToken);
        CompositeAccessToken composite = (CompositeAccessToken)accessToken;
        assertThat("id_token should be JWT, thus longer than 36 characters", composite.getIdTokenValue().length(), greaterThan(36));
        assertThat("Opaque access token must be shorter than 37 characters", accessToken.getValue().length(), lessThanOrEqualTo(36));
        assertThat("Opaque refresh token must be shorter than 37 characters", accessToken.getRefreshToken().getValue().length(), lessThanOrEqualTo(36));

        String accessTokenValue = tokenProvisioning.retrieve(composite.getValue(), IdentityZoneHolder.get().getId()).getValue();
        Map<String,Object> accessTokenClaims = tokenServices.validateToken(accessTokenValue).getClaims();
        assertEquals(true, accessTokenClaims.get(ClaimConstants.REVOCABLE));

        String refreshTokenValue = tokenProvisioning.retrieve(composite.getRefreshToken().getValue(), IdentityZoneHolder.get().getId()).getValue();
        Map<String,Object> refreshTokenClaims = tokenServices.validateToken(refreshTokenValue).getClaims();
        assertEquals(true, refreshTokenClaims.get(ClaimConstants.REVOCABLE));


        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertEquals(USER_AUTHORITIES, loadedAuthentication.getAuthorities());
        assertEquals(tokenSupport.username, loadedAuthentication.getName());
        UaaPrincipal uaaPrincipal = (UaaPrincipal)tokenSupport.defaultUserAuthentication.getPrincipal();
        assertEquals(uaaPrincipal, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertEquals(tokenSupport.username, userAuth.getName());
        assertEquals(uaaPrincipal, userAuth.getPrincipal());
        assertTrue(userAuth.isAuthenticated());

        Map<String,String> params = new HashedMap();
        params.put("grant_type", "refresh_token");
        params.put("client_id",CLIENT_ID);
        OAuth2AccessToken newAccessToken = tokenServices.refreshAccessToken(composite.getRefreshToken().getValue(), new TokenRequest(params, CLIENT_ID, Collections.EMPTY_SET, "refresh_token"));
        System.out.println("newAccessToken = " + newAccessToken);
    }


    @Test
    public void testLoadAuthenticationForAClient() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
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

    @Test(expected = InvalidTokenException.class)
    public void testLoadAuthenticationWithAnExpiredToken() throws InterruptedException {
        BaseClientDetails shortExpiryClient = tokenSupport.defaultClient;
        shortExpiryClient.setAccessTokenValiditySeconds(1);
        tokenSupport.clientDetailsService.setClientDetailsStore(
            IdentityZoneHolder.get().getId(),
            Collections.singletonMap(CLIENT_ID, shortExpiryClient)
        );

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThat(accessToken, validFor(is(1)));

        Thread.sleep(1000l);
        tokenServices.loadAuthentication(accessToken.getValue());
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrantAdditionalAuthorizationAttributes() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        azParameters.put("authorities","{\"az_attr\":{\"external_group\":\"domain\\\\group1\", \"external_id\":\"abcd1234\"}}");
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

    @SuppressWarnings({ "unused", "unchecked" })
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
}
