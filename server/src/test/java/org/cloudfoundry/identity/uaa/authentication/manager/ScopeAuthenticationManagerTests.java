package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.request.DefaultOAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScopeAuthenticationManagerTests {
    private ScopeAuthenticationManager authenticationManager;
    private Map<String, String> clientCredentials;
    private ClientDetailsService service;

    @BeforeEach
    void setUp() {
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
    void passwordAuthenticate() {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken("username", "password");
        assertThat(authenticate(userAuth).isAuthenticated()).isFalse(); //false since we don't authenticate the user yet
    }

    @Test
    void passwordAuthenticateSucceed() {
        UsernamePasswordAuthenticationToken userAuth = new UsernamePasswordAuthenticationToken("username", "password", UaaAuthority.USER_AUTHORITIES);
        assertThat(authenticate(userAuth).isAuthenticated()).isTrue();
    }

    @Test
    void testAuthenticate() {
        assertThat(authenticate(null).isAuthenticated()).isTrue();
    }

    @Test
    void authenticateInsufficientScope() {
        clientCredentials.put("scope", "oauth.approval");
        assertThatExceptionOfType(InsufficientScopeException.class).isThrownBy(() ->
                authenticate(null));
    }

    @Test
    void dedup() {
        List<String> l1 = Arrays.asList("test", "test", "test");
        assertThat(authenticationManager.dedup(l1)).hasSize(1);
        l1 = Arrays.asList("t1", "t2", "t3");
        assertThat(authenticationManager.dedup(l1)).hasSize(3);
    }
}