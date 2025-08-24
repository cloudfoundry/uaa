package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class CompositeTokenGranterTests {

    private CompositeTokenGranter compositeTokenGranter;
    private AuthorizationServerTokenServices tokenServices;
    private ClientDetailsService clientDetailsService;
    private OAuth2RequestFactory oAuth2RequestFactory;
    private TokenRequest tokenRequest;
    private OAuth2Request oauth2Request;

    @BeforeEach
    void setUp() {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(ClientDetailsService.class);
        tokenRequest = mock(TokenRequest.class);
        oauth2Request = mock(OAuth2Request.class);
        AuthorizationCodeServices authorizationCodeServices = mock(AuthorizationCodeServices.class);
        oAuth2RequestFactory = mock(OAuth2RequestFactory.class);
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
        compositeTokenGranter = new CompositeTokenGranter(authenticationManager, oAuth2RequestFactory, clientDetailsService, authorizationCodeServices,
                tokenServices);
    }

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void init() {
        compositeTokenGranter = new CompositeTokenGranter(List.of(mock(ImplicitTokenGranter.class)));
    }

    @Test
    void grant() {
        assertThat(compositeTokenGranter.grant("any", tokenRequest)).isNull();
        compositeTokenGranter.addTokenGranter(new ImplicitTokenGranter(tokenServices, clientDetailsService, oAuth2RequestFactory));
        ClientDetails client = mock(ClientDetails.class);
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(client);
        when(client.getAuthorizedGrantTypes()).thenReturn(Set.of("implicit"));
        Authentication authentication = mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(tokenServices.createAccessToken(any())).thenReturn(mock(OAuth2AccessToken.class));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertThat(compositeTokenGranter.grant("implicit", new ImplicitTokenRequest(tokenRequest, oauth2Request))).isNotNull();
    }

    @Test
    void addTokenGranter() {
        compositeTokenGranter.addTokenGranter(mock(ImplicitTokenGranter.class));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                compositeTokenGranter.addTokenGranter(null));
    }
}