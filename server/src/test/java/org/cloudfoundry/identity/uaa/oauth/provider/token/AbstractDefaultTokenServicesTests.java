package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.ExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.io.Serial;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public abstract class AbstractDefaultTokenServicesTests {

    private DefaultTokenServices services;

    private TokenStore tokenStore;

    @BeforeEach
    public void setUp() throws Exception {
        tokenStore = createTokenStore();
        services = new DefaultTokenServices();
        configureTokenServices(services);
    }

    @Test
    public void clientSpecificRefreshTokenExpiry() {
        getTokenServices().setRefreshTokenValiditySeconds(1000);
        getTokenServices().setClientDetailsService(clientId -> {
            UaaClientDetails client = new UaaClientDetails();
            client.setRefreshTokenValiditySeconds(100);
            client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token"));
            return client;
        });
        OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
        DefaultExpiringOAuth2RefreshToken refreshToken = (DefaultExpiringOAuth2RefreshToken) accessToken
                .getRefreshToken();
        Date expectedExpiryDate = new Date(System.currentTimeMillis() + 102 * 1000L);
        assertThat(expectedExpiryDate.after(refreshToken.getExpiration())).isTrue();
    }

    @Test
    public void clientInvalidated() {
        final AtomicBoolean deleted = new AtomicBoolean();
        DefaultTokenServices tokenServices = getTokenServices();
        tokenServices.setClientDetailsService(clientId -> {
            if (deleted.get()) {
                throw new ClientRegistrationException("No such client: " + clientId);
            }
            UaaClientDetails client = new UaaClientDetails();
            client.setRefreshTokenValiditySeconds(100);
            client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token"));
            return client;
        });
        OAuth2AccessToken token = tokenServices.createAccessToken(createAuthentication());
        deleted.set(true);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() -> tokenServices.loadAuthentication(token.getValue()));
    }

    @Test
    public void refreshedTokenInvalidWithWrongClient() {
        DefaultTokenServices tokenServices = getTokenServices();
        ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) tokenServices
                .createAccessToken(createAuthentication()).getRefreshToken();
        TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "wrong"), "wrong", null,
                null);
        String value = expectedExpiringRefreshToken.getValue();
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() -> tokenServices.refreshAccessToken(value, tokenRequest));
    }

    @Test
    public void refreshedTokenHasNarrowedScopes() {
        ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) getTokenServices()
                .createAccessToken(createAuthentication()).getRefreshToken();
        TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id",
                Collections.singleton("read"), null);
        OAuth2AccessToken refreshedAccessToken = getTokenServices()
                .refreshAccessToken(expectedExpiringRefreshToken.getValue(), tokenRequest);
        assertThat(refreshedAccessToken.getScope()).hasToString("[read]");
    }

    @Test
    public void refreshTokenRequestHasRefreshFlag() {
        ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) getTokenServices()
                .createAccessToken(createAuthentication()).getRefreshToken();
        TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id",
                Collections.singleton("read"), null);
        final AtomicBoolean called = new AtomicBoolean(false);
        getTokenServices().setTokenEnhancer((accessToken, authentication) -> {
            assertThat(authentication.getOAuth2Request().isRefresh()).isTrue();
            called.set(true);
            return accessToken;
        });
        getTokenServices().refreshAccessToken(expectedExpiringRefreshToken.getValue(), tokenRequest);
        assertThat(called.get()).isTrue();
    }

    @Test
    public void refreshTokenNonExpiring() throws Exception {
        ClientDetailsService clientDetailsService = new InMemoryClientDetailsServiceBuilder().withClient("id")
                .refreshTokenValiditySeconds(0).authorizedGrantTypes("refresh_token").and().build();
        DefaultTokenServices tokenServices = getTokenServices();
        tokenServices.setClientDetailsService(clientDetailsService);
        OAuth2RefreshToken refreshToken = tokenServices.createAccessToken(createAuthentication())
                .getRefreshToken();
        assertThat(refreshToken).isNotInstanceOf(ExpiringOAuth2RefreshToken.class);
    }

    @Test
    public void tokenRevoked() {
        OAuth2Authentication authentication = createAuthentication();
        OAuth2AccessToken original = getTokenServices().createAccessToken(authentication);
        services.readAccessToken(original.getValue());
        getTokenStore().removeAccessToken(original);
        assertThat(getTokenStore().findTokensByClientId(authentication.getOAuth2Request().getClientId())).isEmpty();
    }

    @Test
    public void tokenRevokedException() {
        OAuth2Authentication authentication = createAuthentication();
        OAuth2AccessToken original = getTokenServices().createAccessToken(authentication);
        services.readAccessToken(original.getValue());
        services.getClientId(original.getValue());
        getTokenStore().removeAccessToken(original);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                services.loadAuthentication(original.getValue()));
    }

    @Test
    public void getAccessToken() {
        OAuth2Authentication authentication = createAuthentication();
        assertThat(services.getAccessToken(authentication)).isNull();
    }

    @Test
    public void unlimitedTokenExpiry() {
        getTokenServices().setAccessTokenValiditySeconds(0);
        OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
        assertThat(accessToken.getExpiresIn()).isZero();
        assertThat(accessToken.getExpiration()).isNull();
    }

    @Test
    public void defaultTokenExpiry() {
        getTokenServices().setAccessTokenValiditySeconds(100);
        OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
        assertThat(accessToken.getExpiresIn()).isLessThanOrEqualTo(100);
    }

    @Test
    public void clientSpecificTokenExpiry() throws Exception {
        getTokenServices().setAccessTokenValiditySeconds(1000);
        getTokenServices().setClientDetailsService(new ClientDetailsService() {
            public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
                UaaClientDetails client = new UaaClientDetails();
                client.setAccessTokenValiditySeconds(100);
                return client;
            }
        });
        OAuth2AccessToken accessToken = getTokenServices().createAccessToken(createAuthentication());
        assertThat(accessToken.getExpiresIn()).isLessThanOrEqualTo(100);
    }

    @Test
    public void refreshedTokenHasScopes() {
        ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) getTokenServices()
                .createAccessToken(createAuthentication()).getRefreshToken();
        TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
        OAuth2AccessToken refreshedAccessToken = getTokenServices()
                .refreshAccessToken(expectedExpiringRefreshToken.getValue(), tokenRequest);
        assertThat(refreshedAccessToken.getScope()).hasToString("[read, write]");
    }

    @Test
    public void refreshedTokenNotExpiring() {
        getTokenServices().setRefreshTokenValiditySeconds(0);
        OAuth2RefreshToken expectedExpiringRefreshToken = getTokenServices().createAccessToken(createAuthentication())
                .getRefreshToken();
        assertThat(expectedExpiringRefreshToken).isNotInstanceOf(DefaultExpiringOAuth2RefreshToken.class);
    }

    @Test
    public void revokedTokenNotAvailable() {
        OAuth2Authentication authentication = createAuthentication();
        OAuth2AccessToken token = getTokenServices().createAccessToken(authentication);
        getTokenServices().revokeToken(token.getValue());
        Collection<OAuth2AccessToken> tokens = getTokenStore().findTokensByClientIdAndUserName(
                authentication.getOAuth2Request().getClientId(), authentication.getUserAuthentication().getName());
        assertThat(tokens).doesNotContain(token)
                .isEmpty();
    }

    protected void configureTokenServices(DefaultTokenServices services) throws Exception {
        services.setTokenStore(tokenStore);
        services.setSupportRefreshToken(true);
        services.afterPropertiesSet();
    }

    protected abstract TokenStore createTokenStore();

    protected OAuth2Authentication createAuthentication() {
        return new OAuth2Authentication(
                RequestTokenFactory.createOAuth2Request(null, "id", null, false,
                        new LinkedHashSet<>(Arrays.asList("read", "write")), null, null, null, null),
                new TestAuthentication("test2", false));
    }

    protected TokenStore getTokenStore() {
        return tokenStore;
    }

    protected DefaultTokenServices getTokenServices() {
        return services;
    }

    protected static class TestAuthentication extends AbstractAuthenticationToken {

        @Serial
        private static final long serialVersionUID = 1L;

        private final String principal;

        public TestAuthentication(String name, boolean authenticated) {
            super(null);
            setAuthenticated(authenticated);
            this.principal = name;
        }

        public Object getCredentials() {
            return null;
        }

        public Object getPrincipal() {
            return this.principal;
        }
    }
}
