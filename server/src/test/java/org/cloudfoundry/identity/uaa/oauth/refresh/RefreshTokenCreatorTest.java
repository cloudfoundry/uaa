package org.cloudfoundry.identity.uaa.oauth.refresh;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.common.ExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ACR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AMR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RefreshTokenCreatorTest {
    private RefreshTokenCreator refreshTokenCreator;

    @BeforeEach
    void setup() throws Exception {
        TokenValidityResolver validityResolver = mock(TokenValidityResolver.class);
        when(validityResolver.resolve("someclient")).thenReturn(new Date());
        TokenEndpointBuilder tokenEndpointBuilder = new TokenEndpointBuilder("http://localhost");
        refreshTokenCreator = new RefreshTokenCreator(false, validityResolver, tokenEndpointBuilder, new TimeServiceImpl(), new KeyInfoService("http://localhost"));
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("newKey");
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(new HashMap<>(Collections.singletonMap("newKey", "secret")));
    }

    @Test
    void whenRefreshGrantRestricted_throwsExceptionIfOfflineScopeMissing() {
        refreshTokenCreator.setRestrictRefreshGrant(true);
        ArrayList<String> openid = Lists.newArrayList("openid");
        assertThatThrownBy(() -> refreshTokenCreator.ensureRefreshTokenCreationNotRestricted(openid))
                .isInstanceOf(InsufficientScopeException.class)
                .hasMessageContaining("Expected scope uaa.offline_token is missing");
    }

    @Test
    void whenRefreshGrantRestricted_requiresOfflineScope() {
        refreshTokenCreator.setRestrictRefreshGrant(true);
        refreshTokenCreator.ensureRefreshTokenCreationNotRestricted(Lists.newArrayList("openid", "uaa.offline_token"));
    }

    @Test
    void refreshToken_includesClaimsNeededToBuildIdTokens() {
        UaaUser user = new UaaUser(new UaaUserPrototype()
                .withId("id")
                .withEmail("spongebob@krustykrab.com")
                .withUsername("spongebob")
                .withOrigin("uaa")
        );
        Date authTime = new Date(1000L);
        HashSet<String> authenticationMethods = Sets.newHashSet("pwd");
        RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData(
                "refresh_token",
                Sets.newHashSet(),
                authenticationMethods,
                null,
                Sets.newHashSet(),
                "someclient",
                false,
                authTime,
                Sets.newHashSet("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"),
                Maps.newHashMap());

        ExpiringOAuth2RefreshToken refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, "abcdef");

        Map<String, Object> refreshClaims = UaaTokenUtils.getClaims(refreshToken.getValue(), Map.class);
        assertThat(refreshClaims).containsEntry(AUTH_TIME, 1L);
        assertThat((List<String>) refreshClaims.get(AMR)).contains("pwd");
        assertThat((Map<String, List<String>>) refreshClaims.get(ACR)).containsKey("values");
        assertThat(((Map<String, List<String>>) refreshClaims.get(ACR)).get("values")).contains("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
    }

    @Test
    void refreshToken_ifIdTokenClaimsAreUnknown_omitsThem() {
        // This is a backwards compatibility case when trying to construct a new refresh token from an old refresh
        // token issued before auth_time, amr, etc were included in the token claims. We can't show a value for the auth_time
        // because we don't know when the user authenticated.

        UaaUser user = new UaaUser(new UaaUserPrototype()
                .withId("id")
                .withEmail("spongebob@krustykrab.com")
                .withUsername("spongebob")
                .withOrigin("uaa")
        );
        Date authTime = null;
        HashSet<String> authenticationMethods = Sets.newHashSet();
        RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData(
                "refresh_token",
                Sets.newHashSet(),
                authenticationMethods,
                null,
                Sets.newHashSet(),
                "someclient",
                false,
                authTime,
                Sets.newHashSet(),
                Maps.newHashMap());

        ExpiringOAuth2RefreshToken refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, "abcdef");

        Map<String, Object> refreshClaims = UaaTokenUtils.getClaims(refreshToken.getValue(), Map.class);
        assertThat(refreshClaims).doesNotContainKey(AUTH_TIME)
                .doesNotContainKey(AMR)
                .doesNotContainKey(ACR);
    }

    @Test
    void createRefreshToken_whenRefreshRestricted_requiresOfflineScope() {
        UaaUser user = new UaaUser(new UaaUserPrototype()
                .withId("id")
                .withEmail("spongebob@krustykrab.com")
                .withUsername("spongebob")
                .withOrigin("uaa")
        );

        HashSet<String> authenticationMethods = Sets.newHashSet();
        RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData("refresh_token",
                Sets.newHashSet(),
                authenticationMethods,
                null,
                Sets.newHashSet(),
                "someclient",
                false,
                new Date(),
                null,
                Maps.newHashMap());

        refreshTokenCreator.setRestrictRefreshGrant(true);
        ExpiringOAuth2RefreshToken refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, "abcdef");

        assertThat(refreshToken).isNull();
    }

    @Test
    void isRefreshTokenSupported() {
        Set<String> scope = Set.of("openid");
        assertThat(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_AUTHORIZATION_CODE, scope)).isTrue();
        assertThat(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_PASSWORD, scope)).isTrue();
        assertThat(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_USER_TOKEN, scope)).isTrue();
        assertThat(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_REFRESH_TOKEN, scope)).isTrue();
        assertThat(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_SAML2_BEARER, scope)).isTrue();
        assertThat(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_JWT_BEARER, scope)).isTrue();
        assertThat(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_TOKEN_EXCHANGE, scope)).isTrue();
        assertThat(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_CLIENT_CREDENTIALS, scope)).isFalse();
    }
}
