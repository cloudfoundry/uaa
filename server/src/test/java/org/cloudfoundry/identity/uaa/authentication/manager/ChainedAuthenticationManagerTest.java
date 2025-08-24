package org.cloudfoundry.identity.uaa.authentication.manager;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ChainedAuthenticationManagerTest {

    private Authentication success;
    private Authentication failure;
    private AuthenticationManager authenticateTrue;
    private AuthenticationManager authenticateFalse;
    private AuthenticationManager authenticateThrow;
    private ChainedAuthenticationManager.AuthenticationManagerConfiguration[] managers;
    private final ChainedAuthenticationManager authMgr = new ChainedAuthenticationManager();
    private AuthenticationManager loginAuthenticationManager;

    private class UsernamePasswordAuthenticationManager implements AuthenticationManager {
        @Override
        public Authentication authenticate(Authentication authentication)
                throws AuthenticationException {
            final UsernamePasswordAuthenticationToken userToken = (UsernamePasswordAuthenticationToken) authentication;
            String password = (String) authentication.getCredentials();
            return authentication;
        }
    }

    @BeforeEach
    void setUp() {
        success = mock(Authentication.class);
        failure = mock(Authentication.class);

        authenticateTrue = mock(AuthenticationManager.class);
        authenticateFalse = mock(AuthenticationManager.class);
        AuthenticationManager authenticateNull = mock(AuthenticationManager.class);
        authenticateThrow = mock(AuthenticationManager.class);
        loginAuthenticationManager = mock(AuthenticationManager.class);

        when(success.isAuthenticated()).thenReturn(true);
        when(failure.isAuthenticated()).thenReturn(false);
        when(authenticateTrue.authenticate(any(Authentication.class))).thenReturn(success);
        when(loginAuthenticationManager.authenticate(any(Authentication.class))).thenReturn(success);
        when(authenticateFalse.authenticate(any(Authentication.class))).thenReturn(failure);
        when(authenticateNull.authenticate(any(Authentication.class))).thenReturn(null);
        when(authenticateThrow.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("mock throw"));

        managers = new ChainedAuthenticationManager.AuthenticationManagerConfiguration[3];
        managers[0] = new ChainedAuthenticationManager.AuthenticationManagerConfiguration(null, null);
        managers[1] = new ChainedAuthenticationManager.AuthenticationManagerConfiguration(null, ChainedAuthenticationManager.IF_PREVIOUS_FALSE);
        managers[2] = new ChainedAuthenticationManager.AuthenticationManagerConfiguration(loginAuthenticationManager, ChainedAuthenticationManager.IF_PREVIOUS_TRUE);
        authMgr.setDelegates(managers);
    }

    @Test
    void uaaAuthTrue() {
        managers[0].setAuthenticationManager(authenticateTrue);
        managers[1].setAuthenticationManager(authenticateFalse);
        Authentication result = authMgr.authenticate(failure);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        verify(authenticateTrue, times(1)).authenticate(any(Authentication.class));
        verify(authenticateFalse, times(0)).authenticate(any(Authentication.class));
        verify(loginAuthenticationManager, times(0)).authenticate(any(Authentication.class));
    }

    @Test
    void uaaAuthFalseLdapTrue() {
        managers[0].setAuthenticationManager(authenticateFalse);
        managers[1].setAuthenticationManager(authenticateTrue);
        Authentication result = authMgr.authenticate(failure);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        verify(authenticateTrue, times(1)).authenticate(any(Authentication.class));
        verify(authenticateFalse, times(1)).authenticate(any(Authentication.class));
        verify(loginAuthenticationManager, times(1)).authenticate(any(Authentication.class));
    }

    @Test
    void uaaAuthFalseLdapFalse() {
        managers[0].setAuthenticationManager(authenticateFalse);
        managers[1].setAuthenticationManager(authenticateFalse);
        Authentication result = authMgr.authenticate(failure);
        assertThat(result).isNull();
        verify(authenticateFalse, times(2)).authenticate(any(Authentication.class));
        verify(loginAuthenticationManager, times(0)).authenticate(any(Authentication.class));
    }

    @Test
    void uaaAuthThrowLdapAuthFalse() {
        managers[0].setAuthenticationManager(authenticateThrow);
        managers[1].setAuthenticationManager(authenticateFalse);
        try {
            authMgr.authenticate(failure);
            fail("Should have thrown exception");
        } catch (BadCredentialsException ignored) {
        }

        verify(authenticateThrow, times(1)).authenticate(any(Authentication.class));
        verify(authenticateFalse, times(1)).authenticate(any(Authentication.class));
        verify(loginAuthenticationManager, times(0)).authenticate(any(Authentication.class));
    }

    @Test
    void uaaAuthThrowLdapAuthTrue() {
        managers[0].setAuthenticationManager(authenticateThrow);
        managers[1].setAuthenticationManager(authenticateTrue);
        Authentication result = authMgr.authenticate(failure);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        verify(authenticateThrow, times(1)).authenticate(any(Authentication.class));
        verify(authenticateTrue, times(1)).authenticate(any(Authentication.class));
        verify(loginAuthenticationManager, times(1)).authenticate(any(Authentication.class));
    }

    @Test
    void nonStringCredential() {
        when(success.getCredentials()).thenReturn(new Object());

        managers[0].setAuthenticationManager(authenticateThrow);
        managers[1].setAuthenticationManager(new UsernamePasswordAuthenticationManager());
        Authentication result = authMgr.authenticate(success);
        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
        verify(authenticateThrow, times(1)).authenticate(any(Authentication.class));
    }

    @Test
    void nullAuthentication() {
        Authentication result = authMgr.authenticate(null);
        assertThat(result).isNull();
    }
}
