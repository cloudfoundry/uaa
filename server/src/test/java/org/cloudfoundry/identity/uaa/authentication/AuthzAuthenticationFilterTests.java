package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthzAuthenticationFilterTests {

    @Test
    void authenticatesValidUser() throws Exception {
        String msg = "{ \"username\":\"marissa\", \"password\":\"koala\"}";

        AuthenticationManager am = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(am.authenticate(any(AuthzAuthenticationRequest.class))).thenReturn(result);
        AuthzAuthenticationFilter filter = new AuthzAuthenticationFilter(am);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/authorize");
        request.setParameter("credentials", msg);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());
    }

    @Test
    void password_expired_fails_authentication() throws Exception {
        AuthenticationManager am = mock(AuthenticationManager.class);
        UaaAuthentication result = mock(UaaAuthentication.class);
        when(am.authenticate(any(AuthzAuthenticationRequest.class))).thenReturn(result);

        when(result.isAuthenticated()).thenReturn(true);
        when(result.isRequiresPasswordChange()).thenReturn(true);

        AuthzAuthenticationFilter filter = new AuthzAuthenticationFilter(am);
        AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(entryPoint);
        filter.setParameterNames(Arrays.asList("username", "password"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/authorize");
        request.setParameter("username", "marissa");
        request.setParameter("password", "anything");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        ArgumentCaptor<AuthenticationException> captor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(entryPoint, times(1)).commence(same(request), same(response), captor.capture());

        assertEquals(1, captor.getAllValues().size());
        assertEquals(PasswordChangeRequiredException.class, captor.getValue().getClass());
        assertEquals("password change required", captor.getValue().getMessage());
        assertSame(result, ((PasswordChangeRequiredException) captor.getValue()).getAuthentication());
    }
}
