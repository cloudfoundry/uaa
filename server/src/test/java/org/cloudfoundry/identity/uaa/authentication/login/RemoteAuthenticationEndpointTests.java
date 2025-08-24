package org.cloudfoundry.identity.uaa.authentication.login;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.RemoteAuthenticationEndpoint;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginAuthenticationManager;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RemoteAuthenticationEndpointTests {
    private Authentication success;
    private RemoteAuthenticationEndpoint endpoint;
    private AuthenticationManager am;
    private LoginAuthenticationManager loginAuthMgr;
    private OAuth2Authentication loginAuthentication;

    @BeforeEach
    void setUp() {
        UaaPrincipal principal = new UaaPrincipal("user-id-001", "joe", "joe@example.com", OriginKeys.UAA, null, null);
        success = new UsernamePasswordAuthenticationToken(principal, null);

        loginAuthMgr = mock(LoginAuthenticationManager.class);
        am = mock(AuthenticationManager.class);
        endpoint = new RemoteAuthenticationEndpoint(am, loginAuthMgr);
        loginAuthentication = mock(OAuth2Authentication.class);
    }

    @Test
    void successfulAuthenticationGives200Status() {
        when(am.authenticate(any(Authentication.class))).thenReturn(success);
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void accountNotVerifiedExceptionGives403Status() {
        when(am.authenticate(any(Authentication.class))).thenThrow(new AccountNotVerifiedException("failed"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void authenticationExceptionGives401Status() {
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("failed"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void otherExceptionGives500Status() {
        when(am.authenticate(any(Authentication.class))).thenThrow(new RuntimeException("error"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void successfulLoginAuthenticationInvokesLoginAuthManager() {
        SecurityContextHolder.getContext().setAuthentication(loginAuthentication);
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("Invalid authentication manager invoked"));
        when(loginAuthMgr.authenticate(any(Authentication.class))).thenReturn(new UsernamePasswordAuthenticationToken("joe", null));
        when(loginAuthentication.isClientOnly()).thenReturn(Boolean.TRUE);
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "origin", null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

}
