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

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.approval.InMemoryApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2AccessTokenMatchers;
import org.cloudfoundry.identity.uaa.oauth.token.matchers.OAuth2RefreshTokenMatchers;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.AllOf.allOf;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.hamcrest.text.IsEmptyString.isEmptyString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * @author Filip Hanik
 * @author Joel D'sa
 *
 */
public class UaaTokenServicesTests {

    public static final String CLIENT_ID = "client";
    public static final String GRANT_TYPE = "grant_type";
    public static final String PASSWORD = "password";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String AUTOAPPROVE = ClientConstants.AUTO_APPROVE;
    public static final String IMPLICIT = "implicit";
    public static final String UPDATE = "update";
    public static final String CANNOT_READ_TOKEN_CLAIMS = "Cannot read token claims";
    public static final String ISSUER_URI = "http://localhost:8080/uaa/oauth/token";
    public static final String READ = "read";
    public static final String WRITE = "write";
    public static final String DELETE = "delete";
    public static final String ALL_GRANTS_CSV = "authorization_code,password,implicit,client_credentials";
    public static final String CLIENTS = "clients";
    public static final String SCIM = "scim";
    public static final String OPENID = "openid";
    public static final String ROLES = "roles";
    public static final String PROFILE = "profile";

    private TestApplicationEventPublisher<TokenIssuedEvent> publisher;
    private UaaTokenServices tokenServices = new UaaTokenServices();
    private SignerProvider signerProvider = new SignerProvider();

    private List<GrantedAuthority> defaultUserAuthorities = Arrays.asList(
        UaaAuthority.authority("space.123.developer"),
        UaaAuthority.authority("uaa.user"),
        UaaAuthority.authority("space.345.developer"),
        UaaAuthority.authority("space.123.admin"),
        UaaAuthority.authority(READ),
        UaaAuthority.authority(WRITE));

    private String userId = "12345";
    private String username = "jdsa";
    private String email = "jdsa@vmware.com";
    private final String externalId = "externalId";
    private UaaUser defaultUser =
        new UaaUser(
            new UaaUserPrototype()
            .withId(userId)
            .withUsername(username)
            .withPassword(PASSWORD)
            .withEmail(email)
            .withAuthorities(defaultUserAuthorities)
            .withGivenName("Marissa")
            .withFamilyName("Bloggs")
            .withPhoneNumber("1234567890")
            .withCreated(new Date(System.currentTimeMillis() - 15000))
            .withModified(new Date(System.currentTimeMillis() - 15000))
            .withOrigin(OriginKeys.UAA)
            .withExternalId(externalId)
            .withVerified(false)
            .withZoneId(IdentityZoneHolder.get().getId())
            .withSalt(userId)
            .withPasswordLastModified(new Date(System.currentTimeMillis() - 15000)));

    // Need to create a user with a modified time slightly in the past because
    // the token IAT is in seconds and the token
    // expiry
    // skew will not be long enough
    private InMemoryUaaUserDatabase userDatabase = new InMemoryUaaUserDatabase(Collections.singleton(defaultUser));

    private Authentication defaultUserAuthentication = new UsernamePasswordAuthenticationToken(new UaaPrincipal(defaultUser), "n/a", null);

    private InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    private ApprovalStore approvalStore = new InMemoryApprovalStore();
    private MockAuthentication mockAuthentication;
    private List<String> requestedAuthScopes;
    private List<String> clientScopes;
    private List<String> readScope;
    private List<String> writeScope;
    private List<String> expandedScopes;
    public List<String> resourceIds;
    private String expectedJson;
    private BaseClientDetails defaultClient;
    private OAuth2RequestFactory requestFactory;


    public UaaTokenServicesTests() {
        publisher = TestApplicationEventPublisher.forEventClass(TokenIssuedEvent.class);
    }

    @Before
    public void setUp() throws Exception {
        IdentityZoneHolder.clear();
        mockAuthentication = new MockAuthentication();
        SecurityContextHolder.getContext().setAuthentication(mockAuthentication);
        requestedAuthScopes = Arrays.asList(READ, WRITE);
        clientScopes = Arrays.asList(READ, WRITE);
        readScope = Arrays.asList(READ);
        writeScope = Arrays.asList(WRITE);
        expandedScopes = Arrays.asList(READ, WRITE, DELETE);
        resourceIds = Arrays.asList(SCIM, CLIENTS);
        expectedJson = "[\""+READ+"\",\""+WRITE+"\"]";

        defaultClient = new BaseClientDetails(
            CLIENT_ID,
            SCIM+","+CLIENTS,
            READ+","+WRITE,
            ALL_GRANTS_CSV,
            UPDATE);

        clientDetailsService.setClientDetailsStore(
            Collections.singletonMap(
                CLIENT_ID,
                defaultClient
            )
        );
        requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setTokenPolicy(new TokenPolicy(43200, 2592000));
        tokenServices.setDefaultUserAuthorities(AuthorityUtils.authorityListToSet(USER_AUTHORITIES));
        tokenServices.setIssuer("http://localhost:8080/uaa");
        tokenServices.setSignerProvider(signerProvider);
        tokenServices.setUserDatabase(userDatabase);
        tokenServices.setApprovalStore(approvalStore);
        tokenServices.setApplicationEventPublisher(publisher);
        tokenServices.afterPropertiesSet();

        OAuth2AccessTokenMatchers.signer = signerProvider;
        OAuth2RefreshTokenMatchers.signer = signerProvider;
    }

    @After
    public void teardown() {
        IdentityZoneHolder.clear();
        tokenServices.setTokenPolicy(new TokenPolicy(60 * 60 * 12, 60 * 60 * 24 * 30));
    }

    @Test(expected = InvalidTokenException.class)
    public void testNullRefreshTokenString() {
        tokenServices.refreshAccessToken(null, null);
    }

    @Test(expected = InvalidGrantException.class)
    public void testInvalidGrantType() {
        AuthorizationRequest ar = mock(AuthorizationRequest.class);
        tokenServices.refreshAccessToken("", requestFactory.createTokenRequest(ar,"dsdada"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testInvalidRefreshToken() {
        Map<String,String> map = new HashMap<>();
        map.put("grant_type", "refresh_token");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(map,null,null,null,null,null,false,null,null,null);
        tokenServices.refreshAccessToken("dasdasdasdasdas", requestFactory.createTokenRequest(authorizationRequest, "refresh_token"));
    }

    @Test
    public void testCreateAccessTokenForAClient() {

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        tokenServices.setTokenPolicy(new TokenPolicy(60 * 60 * 1, 0));
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertCommonClientAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, zoneId(is(IdentityZoneHolder.get().getId())));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));

        this.assertCommonEventProperties(accessToken, CLIENT_ID, expectedJson);
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
        IdentityZoneHolder.set(identityZone);
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonClientAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is("http://"+subdomain+".localhost:8080/uaa/oauth/token")));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));

        Assert.assertEquals(1, publisher.getEventCount());

        this.assertCommonEventProperties(accessToken, CLIENT_ID, expectedJson);
    }

    private IdentityZone getIdentityZone(String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, scope(is(requestedAuthScopes)));
		assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));
    }

    @Test
    public void testCreateAccessTokenPasswordGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, scope(is(requestedAuthScopes)));
		assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));
    }

    @Test
    public void testCreateRevocableAccessTokenPasswordGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, PASSWORD);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, scope(is(requestedAuthScopes)));
		assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));
    }

    @Test
    public void testCreateAccessTokenRefreshGrant() throws InterruptedException {
        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
		assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
		assertThat(refreshedAccessToken, scope(is(requestedAuthScopes)));
		assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
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
        IdentityZoneHolder.set(identityZone);

        OAuth2AccessToken accessToken = getOAuth2AccessToken();

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
		assertThat(refreshedAccessToken, issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
		assertThat(refreshedAccessToken, scope(is(requestedAuthScopes)));
		assertThat(refreshedAccessToken, validFor(is(3600)));
    }

    private OAuth2AccessToken getOAuth2AccessToken() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 300000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        return tokenServices.createAccessToken(authentication);
    }

    @Test
    public void testCreateAccessTokenRefreshGrantAllScopesAutoApproved() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.addAdditionalInformation(AUTOAPPROVE, "true");
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        // NO APPROVALS REQUIRED

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, scope(is(requestedAuthScopes)));
		assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
		assertThat(refreshedAccessToken, scope(is(requestedAuthScopes)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantSomeScopesAutoApprovedDowngradedRequest() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.addAdditionalInformation(AUTOAPPROVE, Boolean.TRUE.toString());
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        // NO APPROVALS REQUIRED

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, scope(is(requestedAuthScopes)));
		assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,readScope);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
     }

    @Test
    public void testCreateAccessTokenRefreshGrantSomeScopesAutoApproved() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.addAdditionalInformation(AUTOAPPROVE, readScope);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, scope(is(requestedAuthScopes)));
		assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());

        this.assertCommonUserAccessTokenProperties(refreshedAccessToken);
        assertThat(refreshedAccessToken, issuerUri(is(ISSUER_URI)));
        assertThat(refreshedAccessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));
    }

    @Test(expected = InvalidTokenException.class)
    public void testCreateAccessTokenRefreshGrantNoScopesAutoApprovedIncompleteApprovals() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.addAdditionalInformation(AUTOAPPROVE, Arrays.asList());
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, scope(is(requestedAuthScopes)));
		assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testCreateAccessTokenRefreshGrantAllScopesAutoApprovedButApprovalDenied() throws InterruptedException {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.addAdditionalInformation(AUTOAPPROVE, requestedAuthScopes);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.DENIED)
            .setLastUpdatedAt(updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
		assertThat(accessToken, issuerUri(is(ISSUER_URI)));
		assertThat(accessToken, scope(is(requestedAuthScopes)));
		assertThat(accessToken, validFor(is(60 * 60 * 12)));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
        assertNotNull(refreshedAccessToken);
    }

    @Test
    public void testCreateAccessTokenImplicitGrant() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, IMPLICIT);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));
    }

    @Test
    public void create_id_token_with_roles_scope() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, ROLES));
        assertTrue(idTokenJwt.getClaims().contains("\"roles\":[\"group2\",\"group1\"]"));
    }

    @Test
    public void create_id_token_without_roles_scope() {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertFalse(idTokenJwt.getClaims().contains("\"roles\""));
    }

    @Test
    public void create_id_token_with_profile_scope() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID, PROFILE));
        assertTrue(idTokenJwt.getClaims().contains("\"given_name\":\"" + defaultUser.getGivenName() + "\""));
        assertTrue(idTokenJwt.getClaims().contains("\"family_name\":\"" + defaultUser.getFamilyName() + "\""));
        assertTrue(idTokenJwt.getClaims().contains("\"phone_number\":\"" + defaultUser.getPhoneNumber() + "\""));
    }

    @Test
    public void create_id_token_without_profile_scope() throws Exception {
        Jwt idTokenJwt = getIdToken(Arrays.asList(OPENID));
        assertFalse(idTokenJwt.getClaims().contains("\"given_name\":"));
        assertFalse(idTokenJwt.getClaims().contains("\"family_name\":"));
        assertFalse(idTokenJwt.getClaims().contains("\"phone_number\":"));
    }

    private Jwt getIdToken(List<String> scopes) {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, scopes);

        authorizationRequest.setResponseTypes(new HashSet<>(Arrays.asList(CompositeAccessToken.ID_TOKEN)));

        UaaPrincipal uaaPrincipal = new UaaPrincipal(defaultUser.getId(), defaultUser.getUsername(), defaultUser.getEmail(), defaultUser.getOrigin(), defaultUser.getExternalId(), defaultUser.getZoneId());
        UaaAuthentication userAuthentication = new UaaAuthentication(uaaPrincipal, null, defaultUserAuthorities, new HashSet<>(Arrays.asList("group1", "group2")),Collections.EMPTY_MAP, null, true, System.currentTimeMillis(), System.currentTimeMillis() + 1000l * 60l);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);

        return JwtHelper.decodeAndVerify(((CompositeAccessToken) accessToken).getIdTokenValue(), signerProvider.getVerifier());
    }

    @Test
    public void testCreateAccessWithNonExistingScopes() {
        List<String> scopesThatDontExist = Arrays.asList("scope1","scope2");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, scopesThatDontExist);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, IMPLICIT);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is(ISSUER_URI)));
        assertThat(accessToken, scope(is(scopesThatDontExist)));
        assertThat(accessToken, validFor(is(60 * 60 * 12)));
        assertThat(accessToken.getRefreshToken(), is(nullValue()));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(scopesThatDontExist));
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
        IdentityZoneHolder.set(identityZone);

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.assertCommonUserAccessTokenProperties(accessToken);
        assertThat(accessToken, issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken, validFor(is(3600)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is("http://test-zone-subdomain.localhost:8080/uaa/oauth/token")));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(9600)));

		this.assertCommonEventProperties(accessToken, userId, buildJsonString(requestedAuthScopes));
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

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        // First Request
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, scope(is(requestedAuthScopes)));
        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        assertThat(refreshToken, is(not(nullValue())));

        assertThat(refreshToken, OAuth2RefreshTokenMatchers.scope(is(requestedAuthScopes)));
        assertThat(refreshToken, OAuth2RefreshTokenMatchers.audience(is(resourceIds)));

        // Second request with reduced scopes
        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,readScope);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication reducedScopeAuthentication = new OAuth2Authentication(reducedScopeAuthorizationRequest.createOAuth2Request(),userAuthentication);
        OAuth2AccessToken reducedScopeAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(reducedScopeAuthorizationRequest,"refresh_token"));

        // AT should have the new scopes, RT should be the same
        assertThat(reducedScopeAccessToken, scope(is(readScope)));
        assertEquals(reducedScopeAccessToken.getRefreshToken(), accessToken.getRefreshToken());
    }

    @Test(expected = InvalidScopeException.class)
    public void testCreateAccessTokenAuthcodeGrantExpandedScopes() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        // First Request
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        assertThat(accessToken, scope(is(requestedAuthScopes)));
        assertThat(accessToken.getRefreshToken(), is(not(nullValue())));

        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.scope(is(requestedAuthScopes)));
        assertThat(accessToken.getRefreshToken(), OAuth2RefreshTokenMatchers.audience(is(resourceIds)));

        // Second request with expanded scopes
        AuthorizationRequest expandedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,expandedScopes);
        expandedScopeAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(expandedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        expandedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication expandedScopeAuthentication = new OAuth2Authentication(expandedScopeAuthorizationRequest.createOAuth2Request(),userAuthentication);
        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(expandedScopeAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testChangedExpiryForTokens() {
        BaseClientDetails clientDetails = cloneClient(defaultClient);
        clientDetails.setAccessTokenValiditySeconds(3600);
        clientDetails.setRefreshTokenValiditySeconds(36000);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

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

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        UaaUser user = userDatabase.retrieveUserByName(username, OriginKeys.UAA);
        UaaUser newUser = new UaaUser(user.getUsername(), "blah", user.getEmail(), null, null);
        userDatabase.updateUser(userId, newUser);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenExpiry() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));

        BaseClientDetails clientDetails = cloneClient(defaultClient);
        // Back date the refresh token. Crude way to do this but i'm not sure of
        // another
        clientDetails.setRefreshTokenValiditySeconds(-36000);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, clientDetails));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsChanged() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsExpired() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsDenied() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.DENIED));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsMissing() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, -3000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.DENIED));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
    }

    @Test(expected = InvalidTokenException.class)
    public void testRefreshTokenAfterApprovalsMissing2() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest, "refresh_token"));
    }

    @Test
    public void testReadAccessToken() {
        AuthorizationRequest authorizationRequest =new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);
        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertEquals(accessToken, tokenServices.readAccessToken(accessToken.getValue()));
    }

    @Test(expected = InvalidTokenException.class)
    public void testReadAccessTokenForDeletedUserId() {
        AuthorizationRequest authorizationRequest =new AuthorizationRequest(CLIENT_ID, requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);
        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(readScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));
        approvalStore.addApproval(new Approval()
            .setUserId(userId)
            .setClientId(CLIENT_ID)
            .setScope(writeScope.get(0))
            .setExpiresAt(expiresAt.getTime())
            .setStatus(ApprovalStatus.APPROVED)
            .setLastUpdatedAt(updatedAt.getTime()));

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);

        this.userDatabase.clear();
        assertEquals(accessToken, tokenServices.readAccessToken(accessToken.getValue()));
    }

    @Test
    public void testLoadAuthenticationForAUser() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertEquals(USER_AUTHORITIES, loadedAuthentication.getAuthorities());
        assertEquals(username, loadedAuthentication.getName());
        UaaPrincipal uaaPrincipal = (UaaPrincipal)defaultUserAuthentication.getPrincipal();
        assertEquals(uaaPrincipal, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        Authentication userAuth = loadedAuthentication.getUserAuthentication();
        assertEquals(username, userAuth.getName());
        assertEquals(uaaPrincipal, userAuth.getPrincipal());
        assertTrue(userAuth.isAuthenticated());
    }

    @Test
    public void testLoadAuthenticationForAClient() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        OAuth2Authentication loadedAuthentication = tokenServices.loadAuthentication(accessToken.getValue());

        assertEquals(AuthorityUtils.commaSeparatedStringToAuthorityList(UPDATE),loadedAuthentication.getAuthorities());
        assertEquals(CLIENT_ID, loadedAuthentication.getName());
        assertEquals(CLIENT_ID, loadedAuthentication.getPrincipal());
        assertNull(loadedAuthentication.getDetails());

        assertNull(loadedAuthentication.getUserAuthentication());
    }

    @Test(expected = InvalidTokenException.class)
    public void testLoadAuthenticationWithAnExpiredToken() throws InterruptedException {
        BaseClientDetails shortExpiryClient = defaultClient;
        shortExpiryClient.setAccessTokenValiditySeconds(1);
        clientDetailsService.setClientDetailsStore(Collections.singletonMap(CLIENT_ID, shortExpiryClient));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        assertThat(accessToken, validFor(is(1)));

        Thread.sleep(1000l);
        tokenServices.loadAuthentication(accessToken.getValue());
    }

    @Test
    public void testCreateAccessTokenAuthcodeGrantAdditionalAuthorizationAttributes() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        azParameters.put("authorities","{\"az_attr\":{\"external_group\":\"domain\\\\group1\", \"external_id\":\"abcd1234\"}}");
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken token = tokenServices.createAccessToken(authentication);

        OAuth2AccessTokenMatchers.signer = signerProvider;
        this.assertCommonUserAccessTokenProperties(token);
		assertThat(token, issuerUri(is(ISSUER_URI)));
		assertThat(token, scope(is(requestedAuthScopes)));
		assertThat(token, validFor(is(60 * 60 * 12)));

        OAuth2RefreshTokenMatchers.signer = signerProvider;
        OAuth2RefreshToken refreshToken = token.getRefreshToken();
		this.assertCommonUserRefreshTokenProperties(refreshToken);
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.issuerUri(is(ISSUER_URI)));
		assertThat(refreshToken, OAuth2RefreshTokenMatchers.validFor(is(60 * 60 * 24 * 30)));

		this.assertCommonEventProperties(token, userId, buildJsonString(requestedAuthScopes));

        Map<String, String> azMap = new LinkedHashMap<>();
        azMap.put("external_group", "domain\\group1");
        azMap.put("external_id", "abcd1234");
        assertEquals(azMap, token.getAdditionalInformation().get("az_attr"));
    }

    private BaseClientDetails cloneClient(BaseClientDetails client) {
        return new BaseClientDetails(client);
    }

    @SuppressWarnings("unchecked")
    private void assertCommonClientAccessTokenProperties(OAuth2AccessToken accessToken) {
		assertThat(accessToken, allOf(clientId(is(CLIENT_ID)),
						              userId(is(nullValue())),
						              subject(is(CLIENT_ID)),
						              username(is(nullValue())),
						              cid(is(CLIENT_ID)),
						              scope(is(clientScopes)),
						              audience(is(resourceIds)),
						              jwtId(not(isEmptyString())),
						              issuedAt(is(greaterThan(0))),
						              expiry(is(greaterThan(0))),
						              validFor(is(60 * 60 * 1))));
    }

    @SuppressWarnings({ "unused", "unchecked" })
    private void assertCommonUserAccessTokenProperties(OAuth2AccessToken accessToken) {
        assertThat(accessToken, allOf(username(is(username)),
        							  clientId(is(CLIENT_ID)),
        							  subject(is(userId)),
        							  audience(is(resourceIds)),
        							  origin(is(OriginKeys.UAA)),
        							  revocationSignature(is(not(nullValue()))),
        							  cid(is(CLIENT_ID)),
        							  userId(is(userId)),
        							  email(is(email)),
						              jwtId(not(isEmptyString())),
        							  issuedAt(is(greaterThan(0))),
        							  expiry(is(greaterThan(0)))
        							));
    }

    @SuppressWarnings("unchecked")
    private void assertCommonUserRefreshTokenProperties(OAuth2RefreshToken refreshToken) {
        assertThat(refreshToken, allOf(/*issuer(is(issuerUri)),*/
        								OAuth2RefreshTokenMatchers.username(is(username)),
        								OAuth2RefreshTokenMatchers.clientId(is(CLIENT_ID)),
        								OAuth2RefreshTokenMatchers.subject(is(not(nullValue()))),
        								OAuth2RefreshTokenMatchers.audience(is(resourceIds)),
        								OAuth2RefreshTokenMatchers.origin(is(OriginKeys.UAA)),
        								OAuth2RefreshTokenMatchers.revocationSignature(is(not(nullValue()))),
        								OAuth2RefreshTokenMatchers.jwtId(not(isEmptyString())),
        								OAuth2RefreshTokenMatchers.issuedAt(is(greaterThan(0))),
        								OAuth2RefreshTokenMatchers.expiry(is(greaterThan(0)))
        							  )
        		  );
    }

    private void assertCommonEventProperties(OAuth2AccessToken accessToken, String expectedPrincipalId, String expectedData) {
        Assert.assertEquals(1, publisher.getEventCount());

        TokenIssuedEvent event = publisher.getLatestEvent();
        Assert.assertEquals(accessToken, event.getSource());
        Assert.assertEquals(mockAuthentication, event.getAuthentication());
        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals(expectedPrincipalId, auditEvent.getPrincipalId());
        Assert.assertEquals(expectedData, auditEvent.getData());
        Assert.assertEquals(AuditEventType.TokenIssuedEvent, auditEvent.getType());
    }
}
