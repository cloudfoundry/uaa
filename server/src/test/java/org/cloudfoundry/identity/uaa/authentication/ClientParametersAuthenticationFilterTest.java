package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import java.io.IOException;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class ClientParametersAuthenticationFilterTest {

    @Test
    void doesNotContinueWithFilterChain_IfAuthenticationException() throws IOException, ServletException {
        ClientParametersAuthenticationFilter filter = new ClientParametersAuthenticationFilter();

        AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint);

        AuthenticationManager clientAuthenticationManager = mock(AuthenticationManager.class);
        filter.setClientAuthenticationManager(clientAuthenticationManager);

        BadCredentialsException badCredentialsException = new BadCredentialsException("bad credentials");
        when(clientAuthenticationManager.authenticate(Mockito.any())).thenThrow(badCredentialsException);

        MockFilterChain chain = mock(MockFilterChain.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(authenticationEntryPoint).commence(any(request.getClass()), any(response.getClass()), any(BadCredentialsException.class));
        verifyNoMoreInteractions(chain);
    }

    @Test
    void storeClientAuthenticationMethod() throws IOException, ServletException {
        ClientParametersAuthenticationFilter filter = new ClientParametersAuthenticationFilter();

        AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint);
        AuthenticationManager clientAuthenticationManager = mock(AuthenticationManager.class);
        filter.setClientAuthenticationManager(clientAuthenticationManager);

        Authentication authentication = mock(Authentication.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        UaaAuthenticationDetails authenticationDetails = mock(UaaAuthenticationDetails.class);
        when(clientAuthenticationManager.authenticate(Mockito.any())).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getDetails()).thenReturn(authenticationDetails);
        when(authenticationDetails.getAuthenticationMethod()).thenReturn(CLIENT_AUTH_NONE);

        MockFilterChain chain = mock(MockFilterChain.class);
        request.addHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verifyNoInteractions(authenticationEntryPoint);
        verify(chain).doFilter(request, response);
        verify(authenticationDetails, atLeast(1)).getAuthenticationMethod();
    }

    @Test
    void storeClientAuthenticationMethodNoDetails() throws IOException, ServletException {
        ClientParametersAuthenticationFilter filter = new ClientParametersAuthenticationFilter();

        AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint);
        AuthenticationManager clientAuthenticationManager = mock(AuthenticationManager.class);
        filter.setClientAuthenticationManager(clientAuthenticationManager);

        Authentication authentication = mock(Authentication.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        when(clientAuthenticationManager.authenticate(Mockito.any())).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getDetails()).thenReturn(null);

        MockFilterChain chain = mock(MockFilterChain.class);
        request.addHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verifyNoInteractions(authenticationEntryPoint);
        verify(chain).doFilter(request, response);
    }

    @Test
    void storeClientAuthenticationMethodNoMethod() throws IOException, ServletException {
        ClientParametersAuthenticationFilter filter = new ClientParametersAuthenticationFilter();

        AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint);
        AuthenticationManager clientAuthenticationManager = mock(AuthenticationManager.class);
        filter.setClientAuthenticationManager(clientAuthenticationManager);

        Authentication authentication = mock(Authentication.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        UaaAuthenticationDetails authenticationDetails = mock(UaaAuthenticationDetails.class);
        when(clientAuthenticationManager.authenticate(Mockito.any())).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getDetails()).thenReturn(authenticationDetails);
        when(authenticationDetails.getAuthenticationMethod()).thenReturn(null);

        MockFilterChain chain = mock(MockFilterChain.class);
        request.addHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verifyNoInteractions(authenticationEntryPoint);
        verify(chain).doFilter(request, response);
        verify(authenticationDetails).getAuthenticationMethod();
    }
}
