package org.cloudfoundry.identity.uaa.authentication.login;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.RemoteAuthenticationEndpoint;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RemoteAuthenticationEndpointTests {
    private Authentication success;
    private RemoteAuthenticationEndpoint endpoint;
    private AuthenticationManager am;
    private AuthenticationManager loginAuthMgr;
    private OAuth2Authentication loginAuthentication;

    @BeforeEach
    void setUp() {
        UaaPrincipal principal = new UaaPrincipal("user-id-001", "joe", "joe@example.com", OriginKeys.UAA, null, null);
        success = new UsernamePasswordAuthenticationToken(principal, null);

        loginAuthMgr = mock(AuthenticationManager.class);
        am = mock(AuthenticationManager.class);
        endpoint = new RemoteAuthenticationEndpoint(am, loginAuthMgr);
        loginAuthentication = mock(OAuth2Authentication.class);
    }

    @Test
    void successfulAuthenticationGives200Status() {
        when(am.authenticate(any(Authentication.class))).thenReturn(success);
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void accountNotVerifiedExceptionGives403Status() {
        when(am.authenticate(any(Authentication.class))).thenThrow(new AccountNotVerifiedException("failed"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }

    @Test
    void authenticationExceptionGives401Status() {
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("failed"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    void otherExceptionGives500Status() {
        when(am.authenticate(any(Authentication.class))).thenThrow(new RuntimeException("error"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    void successfulLoginAuthenticationInvokesLoginAuthManager() {
        SecurityContextHolder.getContext().setAuthentication(loginAuthentication);
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("Invalid authentication manager invoked"));
        when(loginAuthMgr.authenticate(any(Authentication.class))).thenReturn(new UsernamePasswordAuthenticationToken("joe", null));
        when(loginAuthentication.isClientOnly()).thenReturn(Boolean.TRUE);
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "origin", null);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

}
