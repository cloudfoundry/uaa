package org.cloudfoundry.identity.uaa.oauth.provider.implicit;

import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 * <p>
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 * <p>
 * Scope: OAuth2 server
 */
class ImplicitTokenGranterTests {

    private ImplicitTokenGranter implicitTokenGranter;
    private ImplicitTokenRequest implicitTokenRequest;

    @BeforeEach
    void setUp() {
        AuthorizationServerTokenServices tokenServices = mock(AuthorizationServerTokenServices.class);
        ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);
        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        TokenRequest tokenRequest = mock(TokenRequest.class);
        OAuth2Request oauth2Request = mock(OAuth2Request.class);
        implicitTokenGranter = new ImplicitTokenGranter(tokenServices, clientDetailsService, requestFactory);
        implicitTokenRequest = new ImplicitTokenRequest(tokenRequest, oauth2Request);
    }

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getOAuth2Authentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        implicitTokenGranter.getOAuth2Authentication(mock(ClientDetails.class), implicitTokenRequest);
    }

    @Test
    void getOAuth2AuthenticationException() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(false);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertThatExceptionOfType(InsufficientAuthenticationException.class).isThrownBy(() ->
                implicitTokenGranter.getOAuth2Authentication(mock(ClientDetails.class), implicitTokenRequest));
    }

    @Test
    void setImplicitGrantService() {
        implicitTokenGranter.setImplicitGrantService(null);
    }
}