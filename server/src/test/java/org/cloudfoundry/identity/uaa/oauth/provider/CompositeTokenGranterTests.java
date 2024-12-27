package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Arrays;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class CompositeTokenGranterTests {

    private CompositeTokenGranter compositeTokenGranter;
    private AuthorizationServerTokenServices tokenServices;
    private AuthenticationManager authenticationManager;
    private ClientDetailsService clientDetailsService;
    private OAuth2RequestFactory oAuth2RequestFactory;
    private AuthorizationCodeServices authorizationCodeServices;
    private TokenRequest tokenRequest;
    private OAuth2Request oauth2Request;

    @Before
    public void setUp() throws Exception {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(ClientDetailsService.class);
        tokenRequest = mock(TokenRequest.class);
        oauth2Request = mock(OAuth2Request.class);
        authorizationCodeServices = mock(AuthorizationCodeServices.class);
        oAuth2RequestFactory = mock(OAuth2RequestFactory.class);
        authenticationManager = mock(AuthenticationManager.class);
        compositeTokenGranter = new CompositeTokenGranter(authenticationManager, oAuth2RequestFactory, clientDetailsService, authorizationCodeServices,
                tokenServices);
    }

    @After
    public void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testInit() {
        compositeTokenGranter = new CompositeTokenGranter(Arrays.asList(mock(ImplicitTokenGranter.class)));
    }

    @Test
    public void grant() {
        assertNull(compositeTokenGranter.grant("any", tokenRequest));
        compositeTokenGranter.addTokenGranter(new ImplicitTokenGranter(tokenServices, clientDetailsService, oAuth2RequestFactory));
        ClientDetails client = mock(ClientDetails.class);
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(client);
        when(client.getAuthorizedGrantTypes()).thenReturn(Set.of("implicit"));
        Authentication authentication = mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(tokenServices.createAccessToken(any())).thenReturn(mock(OAuth2AccessToken.class));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertNotNull(compositeTokenGranter.grant("implicit", new ImplicitTokenRequest(tokenRequest, oauth2Request)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void addTokenGranter() {
        compositeTokenGranter.addTokenGranter(mock(ImplicitTokenGranter.class));
        compositeTokenGranter.addTokenGranter(null);
    }
}