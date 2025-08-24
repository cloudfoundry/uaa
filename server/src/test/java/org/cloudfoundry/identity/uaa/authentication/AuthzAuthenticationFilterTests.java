package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
class AuthzAuthenticationFilterTests {

    @Mock
    private AuthenticationManager mockAuthenticationManager;
    private UaaAuthentication mockUaaAuthentication;
    @InjectMocks
    private AuthzAuthenticationFilter authzAuthenticationFilter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        mockUaaAuthentication = mock(UaaAuthentication.class);

        request = new MockHttpServletRequest("POST", "/oauth/authorize");
        response = new MockHttpServletResponse();
    }

    @Test
    void authenticatesValidUser() throws Exception {
        String msg = "{ \"username\":\"marissa\", \"password\":\"koala\"}";
        request.setParameter("credentials", msg);

        authzAuthenticationFilter.doFilter(request, response, new MockFilterChain());
    }

    @Test
    void password_expired_fails_authentication() throws Exception {
        when(mockUaaAuthentication.isAuthenticated()).thenReturn(true);
        MockHttpSession httpSession = new MockHttpSession();
        SessionUtils.setPasswordChangeRequired(httpSession, true);
        request.setSession(httpSession);

        AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
        authzAuthenticationFilter.setAuthenticationEntryPoint(entryPoint);
        authzAuthenticationFilter.setParameterNames(Arrays.asList("username", "password"));

        request.setParameter("username", "marissa");
        request.setParameter("password", "anything");

        when(mockAuthenticationManager.authenticate(any(AuthzAuthenticationRequest.class))).thenReturn(mockUaaAuthentication);

        authzAuthenticationFilter.doFilter(request, response, new MockFilterChain());

        ArgumentCaptor<AuthenticationException> captor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(entryPoint, times(1)).commence(same(request), same(response), captor.capture());

        assertThat(captor.getAllValues()).hasSize(1);
        assertThat(captor.getValue().getClass()).isEqualTo(PasswordChangeRequiredException.class);
        assertThat(captor.getValue().getMessage()).isEqualTo("password change required");
        assertThat(((PasswordChangeRequiredException) captor.getValue()).getAuthentication()).isSameAs(mockUaaAuthentication);
    }
}
