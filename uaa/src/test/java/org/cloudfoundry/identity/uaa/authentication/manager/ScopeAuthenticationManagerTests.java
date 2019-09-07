package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ScopeAuthenticationManagerTests {
    private ScopeAuthenticationManager authenticationManager;
    private Map<String, String> clientCredentials;
    private ClientDetailsService service;

    @Before
    public void setUp() {
        authenticationManager = new ScopeAuthenticationManager();
        authenticationManager.setThrowOnNotAuthenticated(true);
        authenticationManager.setRequiredScopes(Collections.singletonList("oauth.login"));
        clientCredentials = new HashMap<>();
        clientCredentials.put("client_id", "login");
        clientCredentials.put("grant_type", "client_credentials");
        clientCredentials.put("scope", "oauth.login oauth.approval");
        ClientDetails loginClient = mock(ClientDetails.class);
        when(loginClient.getScope()).thenReturn(new HashSet<>(Arrays.asList("oauth.login", "oauth.approval")));
        service = mock(ClientDetailsService.class);
        when(service.loadClientByClientId("login")).thenReturn(loginClient);
    }

    private Authentication authenticate(UsernamePasswordAuthenticationToken userAuth) {
        AuthorizationRequest authorizationRequest = new DefaultOAuth2RequestFactory(service).createAuthorizationRequest(clientCredentials);
        authorizationRequest.setApproved(true);
        OAuth2Request request = authorizationRequest.createOAuth2Request();

        OAuth2Authentication auth = new OAuth2Authentication(request, userAuth);
        return authenticationManager.authenticate(auth);
    }

    @Test
    public void testPasswordAuthenticate() {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken("username", "password");
        assertFalse(authenticate(userAuth).isAuthenticated()); //false since we don't authenticate the user yet
    }

    @Test
    public void testPasswordAuthenticateSucceed() {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken("username", "password", UaaAuthority.USER_AUTHORITIES);
        assertTrue(authenticate(userAuth).isAuthenticated());
    }

    @Test
    public void testAuthenticate() {
        assertTrue(authenticate(null).isAuthenticated());
    }

    @Test(expected = InsufficientScopeException.class)
    public void testAuthenticateInsufficientScope() {
        clientCredentials.put("scope", "oauth.approval");
        authenticate(null);
    }

    @Test
    public void testDedup() {
        List<String> l1 = Arrays.asList("test", "test", "test");
        assertEquals(1, authenticationManager.dedup(l1).size());
        l1 = Arrays.asList("t1", "t2", "t3");
        assertEquals(3, authenticationManager.dedup(l1).size());
    }
}