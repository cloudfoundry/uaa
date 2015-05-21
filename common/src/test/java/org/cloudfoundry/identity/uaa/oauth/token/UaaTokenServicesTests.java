/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.Claims;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.oauth.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.approval.InMemoryApprovalStore;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventPublisher;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
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
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
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

import static org.cloudfoundry.identity.uaa.user.UaaAuthority.USER_AUTHORITIES;
import static org.junit.Assert.assertEquals;
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


    private TestApplicationEventPublisher<TokenIssuedEvent> publisher;
    private UaaTokenServices tokenServices = new UaaTokenServices();
    private SignerProvider signerProvider = new SignerProvider();

    private List<GrantedAuthority> defaultUserAuthorities = Arrays.asList(
        UaaAuthority.authority("space.123.developer"),
        UaaAuthority.authority("uaa.user"),
        UaaAuthority.authority("space.345.developer"),
        UaaAuthority.authority("space.123.admin"));

    private String userId = "12345";
    private String username = "jdsa";
    private String email = "jdsa@vmware.com";
    private final String externalId = "externalId";
    private UaaUser defaultUser =
        new UaaUser(
            userId,
            username,
            PASSWORD,
            email,
            defaultUserAuthorities  ,
            null,
            null,
            new Date(System.currentTimeMillis() - 15000),
            new Date(System.currentTimeMillis() - 15000),
            Origin.UAA,
            externalId,
            false,
            IdentityZoneHolder.get().getId(),
            userId);

    // Need to create a user with a modified time slightly in the past because
    // the token IAT is in seconds and the token
    // expiry
    // skew will not be long enough
    private InMemoryUaaUserDatabase userDatabase =
        new InMemoryUaaUserDatabase(
            new HashMap<>(Collections.singletonMap(username, defaultUser))
        );

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
        tokenServices.setDefaultUserAuthorities(AuthorityUtils.authorityListToSet(USER_AUTHORITIES));
        tokenServices.setIssuer("http://localhost:8080/uaa");
        tokenServices.setSignerProvider(signerProvider);
        tokenServices.setUserDatabase(userDatabase);
        tokenServices.setApprovalStore(approvalStore);
        tokenServices.setApplicationEventPublisher(publisher);
        tokenServices.afterPropertiesSet();
    }

    @After
    public void teardown() {
        IdentityZoneHolder.clear();
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
        map.put("grant_type","refresh_token");
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(map,null,null,null,null,null,false,null,null,null);
        tokenServices.refreshAccessToken("dasdasdasdasdas", requestFactory.createTokenRequest(authorizationRequest,"refresh_token"));
    }


    @Test
    public void testCreateAccessTokenForAClient() {

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.ISS), ISSUER_URI);
        assertEquals(claims.get(Claims.CLIENT_ID), CLIENT_ID);
        assertNull("user_id should be null for a client token", claims.get(Claims.USER_ID));
        assertEquals(claims.get(Claims.SUB), CLIENT_ID);
        assertNull("user_name should be null for a client token", claims.get(Claims.USER_NAME));
        assertEquals(claims.get(Claims.CID), CLIENT_ID);
        assertEquals(claims.get(Claims.SCOPE), clientScopes);
        assertEquals(claims.get(Claims.AUD), resourceIds);
        assertTrue(((String) claims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)) == 60 * 60 * 12);
        assertNull(accessToken.getRefreshToken());
        assertEquals(IdentityZoneHolder.get().getId(), claims.get(Claims.ZONE_ID));

        Assert.assertEquals(1, publisher.getEventCount());

        TokenIssuedEvent event = publisher.getLatestEvent();
        Assert.assertEquals(accessToken, event.getSource());
        Assert.assertEquals(mockAuthentication, event.getAuthentication());
        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals(CLIENT_ID, auditEvent.getPrincipalId());
        Assert.assertEquals(expectedJson, auditEvent.getData());
        Assert.assertEquals(AuditEventType.TokenIssuedEvent, auditEvent.getType());
    }

    @Test
    public void testCreateAccessTokenForAClientInAnotherIdentityZone() {
        String subdomain = "test-zone-subdomain";
        IdentityZoneHolder.set(getIdentityZone(subdomain));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,clientScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, CLIENT_CREDENTIALS);
        authorizationRequest.setRequestParameters(azParameters);

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);

        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(),new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.ISS), "http://"+subdomain+".localhost:8080/uaa/oauth/token");
        assertEquals(claims.get(Claims.CLIENT_ID), CLIENT_ID);
        assertNull("user_id should be null for a client token", claims.get(Claims.USER_ID));
        assertEquals(claims.get(Claims.SUB), CLIENT_ID);
        assertNull("user_name should be null for a client token", claims.get(Claims.USER_NAME));
        assertEquals(claims.get(Claims.CID), CLIENT_ID);
        assertEquals(claims.get(Claims.SCOPE), clientScopes);
        assertEquals(claims.get(Claims.AUD), resourceIds);
        assertTrue(((String) claims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)) == 60 * 60 * 12);
        assertNull(accessToken.getRefreshToken());

        Assert.assertEquals(1, publisher.getEventCount());

        TokenIssuedEvent event = publisher.getLatestEvent();
        Assert.assertEquals(accessToken, event.getSource());
        Assert.assertEquals(mockAuthentication, event.getAuthentication());
        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals(CLIENT_ID, auditEvent.getPrincipalId());
        Assert.assertEquals(expectedJson, auditEvent.getData());
        Assert.assertEquals(AuditEventType.TokenIssuedEvent, auditEvent.getType());
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
        testCreateAccessTokenForAUser(authentication, false);
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
        testCreateAccessTokenForAUser(authentication, false);
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
        testCreateAccessTokenForAUser(authentication, false);
    }


    @Test
    public void testCreateAccessTokenRefreshGrant() throws InterruptedException {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 300000);

        Calendar updatedAt = Calendar.getInstance();
        updatedAt.add(Calendar.MILLISECOND, -1000);

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED, updatedAt.getTime()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED, updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());
        Jwt tokenJwt = JwtHelper.decodeAndVerify(refreshedAccessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(),new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.ISS), ISSUER_URI);
        assertEquals(claims.get(Claims.CLIENT_ID), CLIENT_ID);
        assertEquals(claims.get(Claims.USER_ID), userId);
        assertEquals(claims.get(Claims.SUB), userId);
        assertEquals(claims.get(Claims.USER_NAME), username);
        assertEquals(claims.get(Claims.CID), CLIENT_ID);
        assertEquals(claims.get(Claims.SCOPE), requestedAuthScopes);
        assertEquals(resourceIds, claims.get(Claims.AUD));
        assertTrue(((String) claims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)) == 60 * 60 * 12);
        assertNotNull(accessToken.getRefreshToken());
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
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());
        Jwt tokenJwt = JwtHelper.decodeAndVerify(refreshedAccessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.ISS), ISSUER_URI);
        assertEquals(claims.get(Claims.CLIENT_ID), CLIENT_ID);
        assertEquals(claims.get(Claims.USER_ID), userId);
        assertEquals(claims.get(Claims.SUB), userId);
        assertEquals(claims.get(Claims.USER_NAME), username);
        assertEquals(claims.get(Claims.CID), CLIENT_ID);
        assertEquals(claims.get(Claims.SCOPE), requestedAuthScopes);
        assertEquals(claims.get(Claims.AUD), resourceIds);
        assertTrue(((String) claims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)) == 60 * 60 * 12);
        assertNotNull(accessToken.getRefreshToken());
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
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,readScope);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());
        Jwt tokenJwt = JwtHelper.decodeAndVerify(refreshedAccessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.ISS), ISSUER_URI);
        assertEquals(claims.get(Claims.CLIENT_ID), CLIENT_ID);
        assertEquals(claims.get(Claims.USER_ID), userId);
        assertEquals(claims.get(Claims.SUB), userId);
        assertEquals(claims.get(Claims.USER_NAME), username);
        assertEquals(claims.get(Claims.CID), CLIENT_ID);
        assertEquals(claims.get(Claims.SCOPE), readScope);
        assertEquals(claims.get(Claims.AUD), resourceIds);
        assertTrue(((String) claims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)) == 60 * 60 * 12);
        assertNotNull(accessToken.getRefreshToken());
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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshedAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));

        assertEquals(refreshedAccessToken.getRefreshToken().getValue(), accessToken.getRefreshToken().getValue());
        Jwt tokenJwt = JwtHelper.decodeAndVerify(refreshedAccessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.ISS), ISSUER_URI);
        assertEquals(claims.get(Claims.CLIENT_ID), CLIENT_ID);
        assertEquals(claims.get(Claims.USER_ID), userId);
        assertEquals(claims.get(Claims.SUB), userId);
        assertEquals(claims.get(Claims.USER_NAME), username);
        assertEquals(claims.get(Claims.CID), CLIENT_ID);
        assertEquals(claims.get(Claims.SCOPE), requestedAuthScopes);
        assertEquals(claims.get(Claims.AUD), resourceIds);
        assertTrue(((String) claims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)) == 60 * 60 * 12);
        assertNotNull(accessToken.getRefreshToken());
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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,updatedAt.getTime()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.DENIED,updatedAt.getTime()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2AccessToken refreshToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
        assertNotNull(refreshToken);
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
        testCreateAccessTokenForAUser(authentication, true);
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
        testCreateAccessTokenForAUser(authentication, true, scopesThatDontExist);
    }

    private OAuth2AccessToken testCreateAccessTokenForAUser(OAuth2Authentication authentication, boolean noRefreshToken) {
        return testCreateAccessTokenForAUser(authentication, noRefreshToken, requestedAuthScopes);
    }

    private OAuth2AccessToken testCreateAccessTokenForAUser(OAuth2Authentication authentication, boolean noRefreshToken, List<String> expectedScopes) {
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.ISS), ISSUER_URI);
        assertEquals(claims.get(Claims.CLIENT_ID), CLIENT_ID);
        assertNotNull(claims.get(Claims.USER_ID));
        assertNotNull(claims.get(Claims.SUB));
        assertEquals(claims.get(Claims.USER_NAME), username);
        assertEquals(claims.get(Claims.EMAIL), email);
        assertEquals(claims.get(Claims.CID), CLIENT_ID);
        assertEquals(expectedScopes,claims.get(Claims.SCOPE));
        assertEquals(claims.get(Claims.AUD), resourceIds);
        assertTrue(((String) claims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)) > 0);
        assertNotNull("token revocation signature must be present.",claims.get(Claims.REVOCATION_SIGNATURE));

        if (noRefreshToken) {
            assertNull(accessToken.getRefreshToken());
        } else {
            assertNotNull(accessToken.getRefreshToken());

            Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(accessToken.getRefreshToken().getValue(),signerProvider.getVerifier());
            assertNotNull(refreshTokenJwt);
            Map<String, Object> refreshTokenClaims;
            try {
                refreshTokenClaims = JsonUtils.readValue(refreshTokenJwt.getClaims(),new TypeReference<Map<String, Object>>() {});
            } catch (Exception e) {
                throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
            }

            assertEquals(refreshTokenClaims.get(Claims.ISS), ISSUER_URI);
            assertNotNull(refreshTokenClaims.get(Claims.USER_NAME));
            assertNotNull(refreshTokenClaims.get(Claims.SUB));
            assertEquals(refreshTokenClaims.get(Claims.CID), CLIENT_ID);
            assertEquals(refreshTokenClaims.get(Claims.SCOPE), requestedAuthScopes);
            assertEquals(refreshTokenClaims.get(Claims.AUD), resourceIds);
            if (!noRefreshToken) {
                assertNotNull("token revocation signature must be present.",refreshTokenClaims.get(Claims.REVOCATION_SIGNATURE));
            }
            assertTrue(((String) refreshTokenClaims.get(Claims.JTI)).length() > 0);
            assertTrue(((Integer) refreshTokenClaims.get(Claims.IAT)) > 0);
            assertTrue(((Integer) refreshTokenClaims.get(Claims.EXP)) > 0);
            assertTrue(((Integer) refreshTokenClaims.get(Claims.EXP)) - ((Integer) refreshTokenClaims.get(Claims.IAT)) > 0);
        }

        TokenIssuedEvent event = publisher.getLatestEvent();
        Assert.assertEquals(accessToken, event.getSource());
        Assert.assertEquals(mockAuthentication, event.getAuthentication());
        AuditEvent auditEvent = event.getAuditEvent();
        Assert.assertEquals(userId, auditEvent.getPrincipalId());
        Assert.assertEquals(buildJsonString(expectedScopes), auditEvent.getData());
        Assert.assertEquals(AuditEventType.TokenIssuedEvent, auditEvent.getType());

        return accessToken;
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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,updatedAt.getTime()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,updatedAt.getTime()));

        // First Request
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.SCOPE), requestedAuthScopes);
        assertNotNull(accessToken.getRefreshToken());

        Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(accessToken.getRefreshToken().getValue(),signerProvider.getVerifier());
        assertNotNull(refreshTokenJwt);
        Map<String, Object> refreshTokenClaims;
        try {
            refreshTokenClaims = JsonUtils.readValue(refreshTokenJwt.getClaims(),new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(refreshTokenClaims.get(Claims.SCOPE), requestedAuthScopes);
        assertEquals(refreshTokenClaims.get(Claims.AUD), resourceIds);

        // Second request with reduced scopes
        AuthorizationRequest reducedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,readScope);
        reducedScopeAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(reducedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        reducedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication reducedScopeAuthentication = new OAuth2Authentication(reducedScopeAuthorizationRequest.createOAuth2Request(),userAuthentication);
        OAuth2AccessToken reducedScopeAccessToken = tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(reducedScopeAuthorizationRequest,"refresh_token"));

        // AT should have the new scopes, RT should be the same
        Jwt newTokenJwt = JwtHelper.decodeAndVerify(reducedScopeAccessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> reducedClaims;
        try {
            reducedClaims = JsonUtils.readValue(newTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(reducedClaims.get(Claims.SCOPE), readScope);
        assertEquals(reducedScopeAccessToken.getRefreshToken(), accessToken.getRefreshToken());
    }

    @Test(expected = InvalidScopeException.class)
    public void testCreateAccessTokenAuthcodeGrantExpandedScopes() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));
        // First Request
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = tokenServices.createAccessToken(authentication);
        Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(claims.get(Claims.SCOPE), requestedAuthScopes);
        assertNotNull(accessToken.getRefreshToken());

        Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(accessToken.getRefreshToken().getValue(),signerProvider.getVerifier());
        assertNotNull(refreshTokenJwt);
        Map<String, Object> refreshTokenClaims;
        try {
            refreshTokenClaims = JsonUtils.readValue(refreshTokenJwt.getClaims(),new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertEquals(refreshTokenClaims.get(Claims.SCOPE), requestedAuthScopes);
        assertEquals(refreshTokenClaims.get(Claims.AUD), resourceIds);

        // Second request with expanded scopes
        AuthorizationRequest expandedScopeAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,expandedScopes);
        expandedScopeAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(expandedScopeAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        expandedScopeAuthorizationRequest.setRequestParameters(refreshAzParameters);

        OAuth2Authentication expandedScopeAuthentication = new OAuth2Authentication(expandedScopeAuthorizationRequest.createOAuth2Request(),userAuthentication);
        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(),requestFactory.createTokenRequest(expandedScopeAuthorizationRequest,"refresh_token"));
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
        Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signerProvider.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)) == 3600);
        assertNotNull(accessToken.getRefreshToken());

        Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(accessToken.getRefreshToken().getValue(),signerProvider.getVerifier());
        assertNotNull(refreshTokenJwt);
        Map<String, Object> refreshTokenClaims;
        try {
            refreshTokenClaims = JsonUtils.readValue(refreshTokenJwt.getClaims(),new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        assertTrue(((Integer) refreshTokenClaims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) refreshTokenClaims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) refreshTokenClaims.get(Claims.EXP)) - ((Integer) refreshTokenClaims.get(Claims.IAT)) == 36000);
    }

    @Test(expected = InvalidTokenException.class)
    public void testUserUpdatedAfterRefreshTokenIssued() {
        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

        UaaUser user = userDatabase.retrieveUserByName(username, Origin.UAA);
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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));

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
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

        Calendar expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.MILLISECOND, 3000);

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));

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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.DENIED,new Date()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,new Date()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.DENIED,new Date()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = defaultUserAuthentication;

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

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
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);

        AuthorizationRequest refreshAuthorizationRequest = new AuthorizationRequest(CLIENT_ID,requestedAuthScopes);
        refreshAuthorizationRequest.setResourceIds(new HashSet<>(resourceIds));
        Map<String, String> refreshAzParameters = new HashMap<>(refreshAuthorizationRequest.getRequestParameters());
        refreshAzParameters.put(GRANT_TYPE, REFRESH_TOKEN);
        refreshAuthorizationRequest.setRequestParameters(refreshAzParameters);

        tokenServices.refreshAccessToken(accessToken.getRefreshToken().getValue(), requestFactory.createTokenRequest(refreshAuthorizationRequest,"refresh_token"));
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

        approvalStore.addApproval(new Approval(userId, CLIENT_ID, readScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,updatedAt.getTime()));
        approvalStore.addApproval(new Approval(userId, CLIENT_ID, writeScope.get(0), expiresAt.getTime(), ApprovalStatus.APPROVED,updatedAt.getTime()));

        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);
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
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);
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
        OAuth2AccessToken accessToken = testCreateAccessTokenForAUser(authentication, false);
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
        OAuth2AccessToken token = testCreateAccessTokenForAUser(authentication, false);
        Map<String, String> azMap = new LinkedHashMap<>();
        azMap.put("external_group", "domain\\group1");
        azMap.put("external_id", "abcd1234");
        assertEquals(azMap, token.getAdditionalInformation().get("az_attr"));
    }

    private BaseClientDetails cloneClient(BaseClientDetails client) {
        return new BaseClientDetails(client);
    }
}
