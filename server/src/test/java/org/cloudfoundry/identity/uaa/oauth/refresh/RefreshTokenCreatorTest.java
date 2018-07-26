package org.cloudfoundry.identity.uaa.oauth.refresh;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
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
        refreshTokenCreator = new RefreshTokenCreator(false, validityResolver, tokenEndpointBuilder);
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
    public void refreshToken_includesAuthTime() {
        UaaUser user = new UaaUser(new UaaUserPrototype()
            .withId("id")
            .withEmail("spongebob@krustykrab.com")
            .withUsername("spongebob")
            .withOrigin("uaa")
        );
        Date authTime = new Date(1000L);
        HashSet<String> scopes = Sets.newHashSet();
        HashSet<String> resourceIds = Sets.newHashSet();
        HashMap<String, Object> externalAttributes = Maps.newHashMap();
        RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData("refresh_token", scopes, null, resourceIds, "someclient", false, authTime, externalAttributes);

        ExpiringOAuth2RefreshToken refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, "abcdef");

        assertThat(UaaTokenUtils.getClaims(refreshToken.getValue()).get(AUTH_TIME), is(1));
    }

    @Test
    public void refreshToken_ifAuthTimeIsUnknown_omitsTheAuthTimeClaim() {
        // This is a backwards compatibility case when trying to construct a new refresh token from an old refresh
        // token issued before auth_time was included in the token claims. We can't show a value for the auth_time
        // because we don't know when the user authenticated.

        UaaUser user = new UaaUser(new UaaUserPrototype()
                .withId("id")
                .withEmail("spongebob@krustykrab.com")
                .withUsername("spongebob")
                .withOrigin("uaa")
        );
        Date authTime = null;
        HashSet<String> scopes = Sets.newHashSet();
        HashSet<String> resourceIds = Sets.newHashSet();
        HashMap<String, Object> externalAttributes = Maps.newHashMap();
        RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData("refresh_token", scopes, null, resourceIds, "someclient", false, authTime, externalAttributes);

        ExpiringOAuth2RefreshToken refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, "abcdef");

        assertThat(UaaTokenUtils.getClaims(refreshToken.getValue()).get(AUTH_TIME), is(nullValue()));
    }

    @Test
    public void createRefreshToken_whenRefreshRestricted_requiresOfflineScope() {
        UaaUser user = new UaaUser(new UaaUserPrototype()
            .withId("id")
            .withEmail("spongebob@krustykrab.com")
            .withUsername("spongebob")
            .withOrigin("uaa")
        );

        RefreshTokenRequestData refreshTokenRequestData = new RefreshTokenRequestData("refresh_token", Sets.newHashSet(), null, Sets.newHashSet(), "someclient", false, new Date(), Maps.newHashMap());

        refreshTokenCreator.setRestrictRefreshGrant(true);
        ExpiringOAuth2RefreshToken refreshToken = refreshTokenCreator.createRefreshToken(user, refreshTokenRequestData, "abcdef");

        assertThat(refreshToken, is(nullValue()));
    }
}