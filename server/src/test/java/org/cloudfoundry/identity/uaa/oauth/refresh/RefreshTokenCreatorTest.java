package org.cloudfoundry.identity.uaa.oauth.refresh;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.HashMap;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

public class RefreshTokenCreatorTest {
    private RefreshTokenCreator refreshTokenCreator;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Before
    public void setup() throws Exception {
        TokenValidityResolver validityResolver = mock(TokenValidityResolver.class);
        TokenEndpointBuilder tokenEndpointBuilder = new TokenEndpointBuilder("http://localhost");
        refreshTokenCreator = new RefreshTokenCreator(false, validityResolver, tokenEndpointBuilder);
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
    public void createRefreshToken_whenRefreshRestricted_requiresOfflineScope() {
        UaaUser user = new UaaUser(new UaaUserPrototype()
            .withId("id")
            .withEmail("spongebob@krustykrab.com")
            .withUsername("spongebob")
            .withOrigin("uaa")
        );
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("someclient", Lists.newArrayList());
        authorizationRequest.setRequestParameters(new HashMap() {{
            put("grant_type", "refresh_token");
        }});

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(new UaaPrincipal(user), "n/a", null);
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), usernamePasswordAuthenticationToken);

        refreshTokenCreator.setRestrictRefreshGrant(true);
        ExpiringOAuth2RefreshToken refreshToken = refreshTokenCreator.createRefreshToken(user, "jti", authentication, "abcdef", false, null);

        assertThat(refreshToken, is(nullValue()));
    }
}