package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class DefaultTokenServicesTests {

    private DefaultTokenServices services;
    private final TokenStore tokenStore = Mockito.mock(TokenStore.class);

    @BeforeEach
    void init() throws Exception {
        services = new DefaultTokenServices();
        services.setTokenStore(tokenStore);
        services.afterPropertiesSet();
    }

    @Test
    void accidentalNullAuthentication() {
        Mockito.when(tokenStore.readAccessToken(Mockito.anyString())).thenReturn(
                new DefaultOAuth2AccessToken("FOO"));
        Mockito.when(tokenStore.readAuthentication(Mockito.any(OAuth2AccessToken.class)))
                .thenReturn(null);
        assertThatExceptionOfType(InvalidTokenException.class).isThrownBy(() ->
                services.loadAuthentication("FOO"));
    }

    @Test
    void refreshAccessTokenWithReauthentication() {
        UserDetails user = createMockUser("joeuser", "PROCESSOR");
        UserDetailsService userDetailsService = Mockito.mock(UserDetailsService.class);

        Mockito
                .when(tokenStore.readRefreshToken(Mockito.anyString()))
                .thenReturn(new DefaultOAuth2RefreshToken("FOO"));

        Mockito
                .when(tokenStore.readAuthenticationForRefreshToken(Mockito.any(OAuth2RefreshToken.class)))
                .thenReturn(createMockOAuth2Authentication("myclient", user, "some more details"));

        Mockito
                .when(userDetailsService.loadUserByUsername(Mockito.anyString()))
                .thenReturn(user);

        services.setSupportRefreshToken(true);
        services.setAuthenticationManager(createAuthenticationManager(userDetailsService));

        OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken("FOO", createMockTokenRequest("myclient"));

        ArgumentCaptor<OAuth2Authentication> refreshedAuthenticationCaptor = ArgumentCaptor.forClass(OAuth2Authentication.class);

        Mockito.verify(tokenStore).storeAccessToken(Mockito.eq(refreshedAccessToken), refreshedAuthenticationCaptor.capture());

        OAuth2Authentication refreshedAuthentication = refreshedAuthenticationCaptor.getValue();
        Authentication authentication = refreshedAuthentication.getUserAuthentication();
        assertThat(authentication.getPrincipal()).isEqualTo(user);
        assertThat(authentication.getDetails()).isEqualTo("some more details");
    }

    @Test
    void refreshAccessTokenWithoutReauthentication() {

        UserDetails user = createMockUser("joeuser", "PROCESSOR");

        Mockito
                .when(tokenStore.readRefreshToken(Mockito.anyString()))
                .thenReturn(new DefaultOAuth2RefreshToken("FOO"));

        Mockito
                .when(tokenStore.readAuthenticationForRefreshToken(Mockito.any(OAuth2RefreshToken.class)))
                .thenReturn(createMockOAuth2Authentication("myclient", user, "some more details"));

        services.setSupportRefreshToken(true);
        services.setAuthenticationManager(null);

        OAuth2AccessToken refreshedAccessToken = services.refreshAccessToken("FOO", createMockTokenRequest("myclient"));

        ArgumentCaptor<OAuth2Authentication> refreshedAuthenticationCaptor = ArgumentCaptor.forClass(OAuth2Authentication.class);

        Mockito.verify(tokenStore).storeAccessToken(Mockito.eq(refreshedAccessToken), refreshedAuthenticationCaptor.capture());

        OAuth2Authentication refreshedAuthentication = refreshedAuthenticationCaptor.getValue();
        Authentication authentication = refreshedAuthentication.getUserAuthentication();
        assertThat(authentication.getPrincipal()).isEqualTo(user);
        assertThat(authentication.getDetails()).isEqualTo("some more details");
    }

    private AuthenticationManager createAuthenticationManager(UserDetailsService userDetailsService) {
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(
                new UserDetailsByNameServiceWrapper<>(userDetailsService)
        );
        return new ProviderManager(Arrays.<AuthenticationProvider>asList(provider));
    }

    private TokenRequest createMockTokenRequest(String clientId) {
        return new TokenRequest(null, clientId, null, null);
    }

    private OAuth2Request createMockOAuth2Request(String clientId) {
        return new OAuth2Request(null, clientId, null, true, null, null, null, null, null);
    }

    private OAuth2Authentication createMockOAuth2Authentication(String clientId, UserDetails user, String extraDetails) {
        return new OAuth2Authentication(createMockOAuth2Request(clientId), createMockUserAuthentication(user, extraDetails));
    }

    private UsernamePasswordAuthenticationToken createMockUserAuthentication(UserDetails user, Object extraDetails) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user, "", user.getAuthorities());
        token.setDetails(extraDetails);
        return token;
    }

    private UserDetails createMockUser(String username, String... roles) {
        return new User(username, "", AuthorityUtils.createAuthorityList(roles));
    }
}
