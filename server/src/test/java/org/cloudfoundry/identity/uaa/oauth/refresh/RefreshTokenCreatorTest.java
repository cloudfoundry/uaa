package org.cloudfoundry.identity.uaa.oauth.refresh;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.ExpiringOAuth2RefreshToken;

import java.util.*;

import static com.jayway.jsonassert.impl.matcher.IsMapContainingKey.hasKey;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ACR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AMR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RefreshTokenCreatorTest {
    private RefreshTokenCreator refreshTokenCreator;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();
    private TokenValidityResolver validityResolver;

    @Before
    public void setup() throws Exception {
        validityResolver = mock(TokenValidityResolver.class);
        when(validityResolver.resolve("someclient")).thenReturn(new Date());
        TokenEndpointBuilder tokenEndpointBuilder = new TokenEndpointBuilder("http://localhost");
        refreshTokenCreator = new RefreshTokenCreator(false, validityResolver, tokenEndpointBuilder, new TimeServiceImpl(), new KeyInfoService("http://localhost"));
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setActiveKeyId("newKey");
        IdentityZoneHolder.get().getConfig().getTokenPolicy().setKeys(new HashMap<>(Collections.singletonMap("newKey", "secret")));
    }

    @Test
    public void whenRefreshGrantRestricted_throwsExceptionIfOfflineScopeMissing() {
        expectedEx.expect(InsufficientScopeException.class);
        expectedEx.expectMessage("Expected scope uaa.offline_token is missing");

        refreshTokenCreator.setRestrictRefreshGrant(true);
        refreshTokenCreator.ensureRefreshTokenCreationNotRestricted(Lists.newArrayList("openid"));
    }

    @Test
    public void whenRefreshGrantRestricted_requiresOfflineScope() {
        refreshTokenCreator.setRestrictRefreshGrant(true);
        refreshTokenCreator.ensureRefreshTokenCreationNotRestricted(Lists.newArrayList("openid", "uaa.offline_token"));
    }

    @Test
    public void refreshToken_includesClaimsNeededToBuildIdTokens() {
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
        assertThat(refreshClaims.get(AUTH_TIME), is(1L));
        assertThat((List<String>) refreshClaims.get(AMR), hasItem("pwd"));
        assertThat((Map<String, List<String>>) refreshClaims.get(ACR), hasKey("values"));
        assertThat(((Map<String, List<String>>) refreshClaims.get(ACR)).get("values"), hasItem("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"));
    }

    @Test
    public void refreshToken_ifIdTokenClaimsAreUnknown_omitsThem() {
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
        assertFalse(refreshClaims.containsKey(AUTH_TIME));
        assertFalse(refreshClaims.containsKey(AMR));
        assertFalse(refreshClaims.containsKey(ACR));
    }

    @Test
    public void createRefreshToken_whenRefreshRestricted_requiresOfflineScope() {
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

        assertThat(refreshToken, is(nullValue()));
    }

    @Test
    public void isRefreshTokenSupported() {
        Set<String> scope = Set.of("openid");
        assertTrue(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_AUTHORIZATION_CODE, scope));
        assertTrue(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_PASSWORD, scope));
        assertTrue(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_USER_TOKEN, scope));
        assertTrue(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_REFRESH_TOKEN, scope));
        assertTrue(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_SAML2_BEARER, scope));
        assertTrue(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_JWT_BEARER, scope));
        assertFalse(refreshTokenCreator.isRefreshTokenSupported(
                GRANT_TYPE_CLIENT_CREDENTIALS, scope));
    }
}
