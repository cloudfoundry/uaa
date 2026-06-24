package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
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

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.singleton;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_AUTH_METHOD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_EMPTY;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RefreshRotationTest {

    @Test
    @DisplayName("Refresh Token with concurrent session limit")
    void refreshWithConcurrentSessionLimit() {
        UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));
        
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(true);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setMaxSessionLimit(2);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenRotate(false);

        // Stub getUserTokens
        when(tokenSupport.getTokenProvisioning().getUserTokens(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString())).thenAnswer(invocation -> {
            String userId = invocation.getArgument(0);
            String clientId = invocation.getArgument(1);
            return tokenSupport.tokens.values().stream()
                    .filter(t -> userId.equals(t.getUserId()) && clientId.equals(t.getClientId()))
                    .collect(java.util.stream.Collectors.toList());
        });

        // Stub delete
        org.mockito.Mockito.doAnswer(invocation -> {
            String tokenId = invocation.getArgument(0);
            tokenSupport.tokens.remove(tokenId);
            return null;
        }).when(tokenSupport.getTokenProvisioning()).delete(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.anyString());

        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        Authentication userAuthentication = tokenSupport.defaultUserAuthentication;
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication);
        
        // 1st session
        CompositeToken accessToken1 = (CompositeToken) tokenServices.createAccessToken(authentication);
        String refreshTokenValue1 = accessToken1.getRefreshToken().getValue();
        
        // 2nd session
        CompositeToken accessToken2 = (CompositeToken) tokenServices.createAccessToken(authentication);
        String refreshTokenValue2 = accessToken2.getRefreshToken().getValue();
        
        long refreshTokensCount = tokenSupport.tokens.values().stream().filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).isEqualTo(2);

        // Refresh 2nd session (should reuse the refresh token and NOT delete the 1st session)
        OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue2, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken.getRefreshToken().getValue()).isEqualTo(refreshTokenValue2);
        
        refreshTokensCount = tokenSupport.tokens.values().stream().filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).isEqualTo(2);

        // 3rd session (should delete the oldest session, which is the 1st session)
        CompositeToken accessToken3 = (CompositeToken) tokenServices.createAccessToken(authentication);
        
        refreshTokensCount = tokenSupport.tokens.values().stream().filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).isEqualTo(2);
        
        // Verify that the 1st session's refresh token is no longer in the DB.
        // For opaque-format tokens the tokens map is keyed by tokenId (== the opaque value returned to the client).
        assertThat(tokenSupport.tokens.containsKey(refreshTokenValue1))
                .as("1st session refresh token must be gone after 3rd login").isFalse();
    }

    @Test
    @DisplayName("Concurrent session limit with public client rotation (tp_cli_app scenario)")
    void refreshWithConcurrentSessionLimitAndPublicClientRotation() {
        // tp_cli_app is a public client (allowpublic=true, no secret).
        // shouldRotateRefreshTokens() returns true whenever clientAuth == "none",
        // so every access-token refresh produces a new refresh token JTI.
        // The bug: enforceConcurrentSessionLimit treated each rotation as a net +1
        // new session, causing premature revocation of older sessions.

        UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));

        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(true);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setMaxSessionLimit(2);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenRotate(false); // global off; rotation is forced by clientAuth=none

        when(tokenSupport.getTokenProvisioning().getUserTokens(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString())).thenAnswer(invocation -> {
            String userId = invocation.getArgument(0);
            String clientId = invocation.getArgument(1);
            return tokenSupport.tokens.values().stream()
                    .filter(t -> userId.equals(t.getUserId()) && clientId.equals(t.getClientId()))
                    .collect(java.util.stream.Collectors.toList());
        });
        org.mockito.Mockito.doAnswer(invocation -> {
            tokenSupport.tokens.remove((String) invocation.getArgument(0));
            return null;
        }).when(tokenSupport.getTokenProvisioning()).delete(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.anyString());

        // Build a public-client OAuth2Request (clientAuth = "none")
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
        OAuth2Request publicOAuth2Request = authorizationRequest.createOAuth2Request();
        OAuth2Authentication publicAuthentication = new OAuth2Authentication(publicOAuth2Request, tokenSupport.defaultUserAuthentication);

        // Host A logs in (1st session)
        CompositeToken accessToken1 = (CompositeToken) tokenServices.createAccessToken(publicAuthentication);
        String refreshTokenValue1 = accessToken1.getRefreshToken().getValue();

        // Host B logs in (2nd session)
        CompositeToken accessToken2 = (CompositeToken) tokenServices.createAccessToken(publicAuthentication);
        String refreshTokenValue2 = accessToken2.getRefreshToken().getValue();

        long refreshTokensCount = tokenSupport.tokens.values().stream()
                .filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).isEqualTo(2);

        // Host B's CLI proactively refreshes (60 s access-token TTL triggers rotation).
        // This must NOT revoke Host A's session.
        setupOAuth2Authentication(publicOAuth2Request);
        OAuth2AccessToken refreshedToken2 = tokenServices.refreshAccessToken(refreshTokenValue2,
                new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        String rotatedRefreshTokenValue2 = refreshedToken2.getRefreshToken().getValue();
        assertThat(rotatedRefreshTokenValue2).as("rotation must produce a new token value").isNotEqualTo(refreshTokenValue2);

        refreshTokensCount = tokenSupport.tokens.values().stream()
                .filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).as("rotation must not shrink the session count below the limit").isEqualTo(2);
        assertThat(tokenSupport.tokens.containsKey(refreshTokenValue1))
                .as("Host A session must still be active after Host B rotates").isTrue();

        // Host C logs in (3rd session) — must evict only Host A (the oldest session).
        CompositeToken accessToken3 = (CompositeToken) tokenServices.createAccessToken(publicAuthentication);

        refreshTokensCount = tokenSupport.tokens.values().stream()
                .filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).isEqualTo(2);
        // For opaque-format tokens the map key is the token ID (the opaque value returned to the client),
        // not the full JWT stored as the value, so we check with containsKey.
        assertThat(tokenSupport.tokens.containsKey(refreshTokenValue1))
                .as("Host A's original refresh token must be evicted after 3rd login").isFalse();

        // Host C's CLI immediately rotates its own token — must NOT evict Host B.
        setupOAuth2Authentication(publicOAuth2Request);
        OAuth2AccessToken refreshedToken3 = tokenServices.refreshAccessToken(accessToken3.getRefreshToken().getValue(),
                new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));

        refreshTokensCount = tokenSupport.tokens.values().stream()
                .filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).as("Host C's rotation must not evict Host B").isEqualTo(2);
        assertThat(tokenSupport.tokens.containsKey(rotatedRefreshTokenValue2))
                .as("Host B session must still be active after Host C rotates").isTrue();
    }

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
    @DisplayName("Concurrent session limit with confidential client (tp_app / Hub UI scenario)")
    void refreshWithConcurrentSessionLimitAndConfidentialClient() {
        // tp_app (Hub UI) authenticates with a client secret.
        // shouldRotateRefreshTokens() returns false because clientAuth is null (not "none").
        // The same refresh-token JTI is reused on every access-token refresh, so the old
        // formula also caused no problem here — but we add this test to confirm our fix
        // does not regress that behaviour.

        UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));

        IdentityZoneHolder.get().getConfig().getTokenPolicy().setJwtRevocable(true);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setMaxSessionLimit(2);
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setRefreshTokenRotate(false);

        when(tokenSupport.getTokenProvisioning().getUserTokens(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString())).thenAnswer(invocation -> {
            String userId = invocation.getArgument(0);
            String clientId = invocation.getArgument(1);
            return tokenSupport.tokens.values().stream()
                    .filter(t -> userId.equals(t.getUserId()) && clientId.equals(t.getClientId()))
                    .collect(java.util.stream.Collectors.toList());
        });
        org.mockito.Mockito.doAnswer(invocation -> {
            tokenSupport.tokens.remove((String) invocation.getArgument(0));
            return null;
        }).when(tokenSupport.getTokenProvisioning()).delete(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.anyString());

        // Confidential-client request: no CLIENT_AUTH_NONE extension → clientAuth = null
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        OAuth2Request confidentialOAuth2Request = authorizationRequest.createOAuth2Request();
        OAuth2Authentication confidentialAuthentication = new OAuth2Authentication(confidentialOAuth2Request, tokenSupport.defaultUserAuthentication);

        // Session 1 (browser tab on machine A)
        CompositeToken accessToken1 = (CompositeToken) tokenServices.createAccessToken(confidentialAuthentication);
        String refreshTokenValue1 = accessToken1.getRefreshToken().getValue();

        // Session 2 (browser tab on machine B)
        CompositeToken accessToken2 = (CompositeToken) tokenServices.createAccessToken(confidentialAuthentication);
        String refreshTokenValue2 = accessToken2.getRefreshToken().getValue();

        long refreshTokensCount = tokenSupport.tokens.values().stream()
                .filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).isEqualTo(2);

        // Session 2 refreshes its access token (no rotation: same JTI is reused).
        // This must NOT evict session 1.
        setupOAuth2Authentication(confidentialOAuth2Request);
        OAuth2AccessToken refreshedToken2 = tokenServices.refreshAccessToken(refreshTokenValue2,
                new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken2.getRefreshToken().getValue())
                .as("confidential client must reuse the same refresh token (no rotation)").isEqualTo(refreshTokenValue2);

        refreshTokensCount = tokenSupport.tokens.values().stream()
                .filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).as("refresh without rotation must not change the session count").isEqualTo(2);
        assertThat(tokenSupport.tokens.containsKey(refreshTokenValue1))
                .as("session 1 must still be active after session 2 refreshes").isTrue();

        // Session 3 logs in — must evict only session 1 (the oldest).
        CompositeToken accessToken3 = (CompositeToken) tokenServices.createAccessToken(confidentialAuthentication);

        refreshTokensCount = tokenSupport.tokens.values().stream()
                .filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).as("3rd login must keep the count at the limit").isEqualTo(2);
        assertThat(tokenSupport.tokens.containsKey(refreshTokenValue1))
                .as("session 1 (oldest) must be evicted after 3rd login").isFalse();
        assertThat(tokenSupport.tokens.containsKey(refreshTokenValue2))
                .as("session 2 must still be active after 3rd login").isTrue();

        // Session 3 refreshes (still no rotation for confidential client).
        // Must NOT evict session 2.
        setupOAuth2Authentication(confidentialOAuth2Request);
        tokenServices.refreshAccessToken(accessToken3.getRefreshToken().getValue(),
                new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));

        refreshTokensCount = tokenSupport.tokens.values().stream()
                .filter(t -> org.cloudfoundry.identity.uaa.oauth.token.RevocableToken.TokenType.REFRESH_TOKEN.equals(t.getResponseType())).count();
        assertThat(refreshTokensCount).as("session 3 refresh must not evict session 2").isEqualTo(2);
        assertThat(tokenSupport.tokens.containsKey(refreshTokenValue2))
                .as("session 2 must still be active after session 3 refreshes").isTrue();
    }

    @Test
    @DisplayName("Refresh Token with rotation")
    void refreshRotation() {
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
        assertThat(refreshTokenValue).isNotNull();

        OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken).isNotNull();
        assertThat(refreshedToken.getRefreshToken().getValue()).as("New refresh token should be equal to the old one.").isEqualTo(refreshTokenValue);

        new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(true);

        Map<String, RevocableToken> tokens = tokenSupport.tokens;
        refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken.getRefreshToken().getValue()).as("New access token should be different from the old one.").isNotEqualTo(refreshTokenValue);

    }

    @Test
    @DisplayName("Refresh Token with allowpublic and rotation")
    void refreshPublicClientWithRotation() {
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

        assertThat((Map<String, Object>) UaaTokenUtils.getClaims(accessToken.getValue(), Map.class)).containsEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);
        String refreshTokenValue = accessToken.getRefreshToken().getValue();
        assertThat(refreshTokenValue).isNotNull();

        setupOAuth2Authentication(oAuth2Request);
        OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken).isNotNull();
        assertThat(refreshedToken.getRefreshToken().getValue()).as("New access token should be different from the old one.").isNotEqualTo(refreshTokenValue);
        assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class)).containsEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);

        refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken.getRefreshToken().getValue()).as("New access token should be different from the old one.").isNotEqualTo(refreshTokenValue);
        assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class)).containsEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);
    }

    @Test
    @DisplayName("Refresh Token from public to empty authentication")
    void refreshPublicClientWithRotationAndEmpyAuthentication() {
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

        assertThat((Map<String, Object>) UaaTokenUtils.getClaims(accessToken.getValue(), Map.class)).containsEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);
        String refreshTokenValue = accessToken.getRefreshToken().getValue();
        assertThat(refreshTokenValue).isNotNull();

        authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_EMPTY));
        setupOAuth2Authentication(authorizationRequest.createOAuth2Request());
        OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken).isNotNull();
        assertThat(refreshedToken.getRefreshToken().getValue()).as("New access token should be different from the old one.").isNotEqualTo(refreshTokenValue);
        assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class)).containsEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);

        refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken.getRefreshToken().getValue()).as("New access token should be different from the old one.").isNotEqualTo(refreshTokenValue);
        assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class)).containsEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);
    }

    @Test
    @DisplayName("Refresh Token with allowpublic and implicit rotation")
    void refreshPublicClientImplicitRotation() {
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

        assertThat((Map<String, Object>) UaaTokenUtils.getClaims(accessToken.getValue(), Map.class)).containsEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);
        String refreshTokenValue = accessToken.getRefreshToken().getValue();
        assertThat(refreshTokenValue).isNotNull();

        setupOAuth2Authentication(oAuth2Request);
        OAuth2AccessToken refreshedToken = tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN));
        assertThat(refreshedToken).isNotNull();
        assertThat(refreshedToken.getRefreshToken().getValue()).as("New access token should be different from the old one.").isNotEqualTo(refreshTokenValue);
        assertThat((Map<String, Object>) UaaTokenUtils.getClaims(refreshedToken.getValue(), Map.class)).containsEntry(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE);
    }

    @Test
    @DisplayName("Refresh with allowpublic and rotation but existing token was not public")
    void refreshPublicClientButExistingTokenWasEmptyAuthentication() {
        UaaClientDetails clientDetails = new UaaClientDetails(tokenSupport.defaultClient);
        clientDetails.setAutoApproveScopes(singleton("true"));
        tokenSupport.clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap(CLIENT_ID, clientDetails));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest(CLIENT_ID, tokenSupport.requestedAuthScopes);
        authorizationRequest.setResourceIds(new HashSet<>(tokenSupport.resourceIds));
        Map<String, String> azParameters = new HashMap<>(authorizationRequest.getRequestParameters());
        azParameters.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        authorizationRequest.setRequestParameters(azParameters);
        OAuth2Request oAuth2Request = authorizationRequest.createOAuth2Request();
        OAuth2Authentication authentication = new OAuth2Authentication(oAuth2Request, tokenSupport.defaultUserAuthentication);
        new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(true);
        CompositeToken accessToken = (CompositeToken) tokenServices.createAccessToken(authentication);

        String refreshTokenValue = accessToken.getRefreshToken().getValue();
        assertThat(refreshTokenValue).isNotNull();

        new IdentityZoneManagerImpl().getCurrentIdentityZone().getConfig().getTokenPolicy().setRefreshTokenRotate(false);
        authorizationRequest.setExtensions(Map.of(CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
        setupOAuth2Authentication(authorizationRequest.createOAuth2Request());
        assertThatThrownBy(() ->
                tokenServices.refreshAccessToken(refreshTokenValue, new TokenRequest(new HashMap<>(), CLIENT_ID, Lists.newArrayList("openid"), GRANT_TYPE_REFRESH_TOKEN)))
                .isInstanceOf(TokenRevokedException.class)
                .hasMessage("Refresh without client authentication not allowed.");
    }

    private static Authentication setupOAuth2Authentication(OAuth2Request auth2Request) {
        OAuth2Authentication authentication = mock(OAuth2Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.getOAuth2Request()).thenReturn(auth2Request);
        return authentication;
    }
}
