package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.ExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public abstract class AbstractPersistentDefaultTokenServicesTests extends AbstractDefaultTokenServicesTests {

    @Test
    public void tokenEnhancerUpdatesStoredTokens() {
        final ExpiringOAuth2RefreshToken refreshToken = new DefaultExpiringOAuth2RefreshToken("testToken", new Date(
                System.currentTimeMillis() + 100000));
        getTokenServices().setTokenEnhancer((accessToken, authentication) -> {
            DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
            result.setRefreshToken(refreshToken);
            return result;
        });
        OAuth2Authentication authentication = createAuthentication();
        OAuth2AccessToken original = getTokenServices().createAccessToken(authentication);
        assertThat(refreshToken).isEqualTo(original.getRefreshToken());
        OAuth2AccessToken result = getTokenStore().getAccessToken(authentication);
        assertThat(result).isEqualTo(original);
        assertThat(result.getRefreshToken()).isEqualTo(refreshToken);
        assertThat(getTokenStore().readRefreshToken(refreshToken.getValue())).isEqualTo(refreshToken);
    }

    @Test
    public void refreshedTokenIsEnhanced() {
        getTokenServices().setTokenEnhancer((accessToken, authentication) -> {
            DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
            result.setValue("I'mEnhanced");
            return result;
        });

        OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
        assertThat(accessToken.getValue()).startsWith("I'mEnhanced");
        TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
        OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
                accessToken.getRefreshToken().getValue(), tokenRequest);
        assertThat(refreshedAccessToken.getValue()).startsWith("I'mEnhanced");
    }

    @Test
    public void oneAccessTokenPerAuthentication() {
        OAuth2Authentication authentication = createAuthentication();
        OAuth2AccessToken first = getTokenServices().createAccessToken(authentication);
        assertThat(getAccessTokenCount()).isOne();
        assertThat(getRefreshTokenCount()).isOne();
        OAuth2AccessToken second = getTokenServices().createAccessToken(authentication);
        assertThat(second).isEqualTo(first);
        assertThat(getAccessTokenCount()).isOne();
        assertThat(getRefreshTokenCount()).isOne();
    }

    @Test
    public void oneAccessTokenPerUniqueAuthentication() {
        getTokenServices()
                .createAccessToken(
                        new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false,
                                Collections.singleton("read")), new TestAuthentication("test2",
                                false)));
        assertThat(getAccessTokenCount()).isOne();
        getTokenServices()
                .createAccessToken(
                        new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false,
                                Collections.singleton("write")), new TestAuthentication(
                                "test2", false)));
        assertThat(getAccessTokenCount()).isOne();
    }

    @Test
    public void refreshTokenMaintainsState() {
        getTokenServices().setSupportRefreshToken(true);
        OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
        OAuth2RefreshToken expectedExpiringRefreshToken = accessToken.getRefreshToken();
        TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
        OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
                expectedExpiringRefreshToken.getValue(), tokenRequest);
        assertThat(refreshedAccessToken).isNotNull();
        assertThat(getAccessTokenCount()).isOne();
    }

    @Test
    public void notReuseRefreshTokenMaintainsState() {
        getTokenServices().setSupportRefreshToken(true);
        getTokenServices().setReuseRefreshToken(false);
        OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
        OAuth2RefreshToken expectedExpiringRefreshToken = accessToken.getRefreshToken();
        TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
        OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
                expectedExpiringRefreshToken.getValue(), tokenRequest);
        assertThat(refreshedAccessToken).isNotNull();
        assertThat(getRefreshTokenCount()).isOne();
    }

    protected abstract int getAccessTokenCount();

    protected abstract int getRefreshTokenCount();
}
