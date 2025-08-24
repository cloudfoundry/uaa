package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class InMemoryTokenStoreTests extends TokenStoreBaseTests {

    private InMemoryTokenStore tokenStore;

    @Override
    public InMemoryTokenStore getTokenStore() {
        return tokenStore;
    }

    @BeforeEach
    void createStore() {
        AuthenticationKeyGenerator dummyKeyGenerator = new AuthenticationKeyGenerator() {
            private final String key = new AlphanumericRandomValueStringGenerator(10).generate();

            @Override
            public String extractKey(OAuth2Authentication authentication) {
                return key;
            }
        };
        tokenStore = new InMemoryTokenStore();
        tokenStore.clear();
        tokenStore.setAuthenticationKeyGenerator(dummyKeyGenerator);
    }

    @Test
    void tokenCountConsistency() {
        for (int i = 0; i <= 10; i++) {
            OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id" + i, false), new TestAuthentication("test", false));
            DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken" + i);
            expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
            getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
            assertThat(expectedOAuth2AccessToken).isNotNull();
        }
    }

    @Test
    void tokenCountConsistentWithExpiryQueue() {
        OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test", false));
        DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
        expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
        for (int i = 0; i <= 10; i++) {
            getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
            assertThat(getTokenStore().getExpiryTokenCount()).isEqualTo(getTokenStore().getAccessTokenCount());
            assertThat(getTokenStore().getRefreshTokenCount()).isOne();
        }
    }

    @Test
    void autoFlush() {
        getTokenStore().setFlushInterval(3);
        assertThat(getTokenStore().getFlushInterval()).isEqualTo(3);
        for (int i = 0; i <= 10; i++) {
            OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
                    RequestTokenFactory.createOAuth2Request("id" + i, false), new TestAuthentication("test", false));
            DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken" + i);
            expectedOAuth2AccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
            getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
            assertThat(expectedOAuth2AccessToken).isNotNull();
        }
    }
}
