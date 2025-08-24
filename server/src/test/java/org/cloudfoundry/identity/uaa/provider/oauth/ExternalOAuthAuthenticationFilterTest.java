package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.web.HttpSessionRequiredException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.function.Consumer;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ExternalOAuthAuthenticationFilterTest {
    private static final String ORIGIN_KEY = "the_origin";
    private static final String OAUTH_STATE = "the_state";
    private ExternalOAuthAuthenticationFilter externalOAuthAuthenticationFilter;
    private ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private FilterChain mockFilterChain;

    @BeforeEach
    void setUp() {
        externalOAuthAuthenticationManager = mock(ExternalOAuthAuthenticationManager.class);
        mockFilterChain = mock(FilterChain.class);
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WhenAuthenticationSucceeds {

        @Test
        void itShouldCallTheNextFilter() throws IOException, ServletException {
            externalOAuthAuthenticationFilter = new ExternalOAuthAuthenticationFilter(externalOAuthAuthenticationManager, null);
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, OAUTH_STATE);
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
            verify(mockFilterChain).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itCallsTheSuccessHandler() throws IOException, ServletException {
            AccountSavingAuthenticationSuccessHandler successHandler = mock(AccountSavingAuthenticationSuccessHandler.class);
            Authentication mockAuthentication = mock(Authentication.class);
            when(externalOAuthAuthenticationManager.authenticate(any())).thenReturn(mockAuthentication);

            externalOAuthAuthenticationFilter = new ExternalOAuthAuthenticationFilter(externalOAuthAuthenticationManager, successHandler);
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, OAUTH_STATE);
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
            verify(mockFilterChain).doFilter(mockRequest, mockResponse);
            verify(successHandler).setSavedAccountOptionCookie(mockRequest, mockResponse, mockAuthentication);
        }
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WhenAuthenticationFails {
        @BeforeEach
        void setUp() {
            externalOAuthAuthenticationFilter = new ExternalOAuthAuthenticationFilter(externalOAuthAuthenticationManager, null);
            when(externalOAuthAuthenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("your credentials are bad yo"));
        }

        @Test
        void itShouldNotCallTheNextFilter() throws IOException, ServletException {
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, OAUTH_STATE);
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WhenValidatingStateParameter {
        @BeforeEach
        void setUp() {
            externalOAuthAuthenticationFilter = new ExternalOAuthAuthenticationFilter(externalOAuthAuthenticationManager, null);
        }

        @Test
        void itThrowsIfNoSession() throws IOException, ServletException {
            HttpServletRequest mockRequest = mockRedirectRequest(false, ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatExceptionOfType(HttpSessionRequiredException.class).isThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itThrowsIfNoStateInSession() throws IOException, ServletException {
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatExceptionOfType(CsrfException.class).isThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itThrowsIfNoStateInRequest() throws IOException, ServletException {
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatExceptionOfType(CsrfException.class).isThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itThrowsIfStateIsMismatched() throws IOException, ServletException {
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, "surprise");
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatExceptionOfType(CsrfException.class).isThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }
    }

    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WhenNoCredentialsPresent {
        @BeforeEach
        void setUp() {
            externalOAuthAuthenticationFilter = new ExternalOAuthAuthenticationFilter(externalOAuthAuthenticationManager, null);
        }

        @Test
        void itRedirects() throws IOException, ServletException {
            RequestDispatcher mockRequestDispatcher = mock(RequestDispatcher.class);

            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockStateParamInRequest(request, OAUTH_STATE);
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, OAUTH_STATE);
                when(request.getRequestDispatcher("/login_implicit")).thenReturn(mockRequestDispatcher);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
            verify(mockRequestDispatcher).forward(mockRequest, mockResponse);
        }

        @Test
        void itRedirects_EvenWhenTheStateHasNotYetBeenPulledFromTheHashFragmentYet()
                throws IOException, ServletException {
            RequestDispatcher mockRequestDispatcher = mock(RequestDispatcher.class);

            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request ->
                    when(request.getRequestDispatcher("/login_implicit")).thenReturn(mockRequestDispatcher));
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
            verify(mockRequestDispatcher).forward(mockRequest, mockResponse);
        }
    }

    private HttpServletRequest mockRedirectRequest(String origin, Consumer<HttpServletRequest> config) {
        return mockRedirectRequest(true, origin, config);
    }

    private HttpServletRequest mockRedirectRequest(boolean includeSession, String origin, Consumer<HttpServletRequest> config) {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getContextPath()).thenReturn("/uaa");
        when(mockRequest.getRequestURI()).thenReturn("/uaa/login/callback/" + origin);
        when(mockRequest.getServletPath()).thenReturn("login/callback/" + origin);
        when(mockRequest.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/" + origin));

        if (includeSession) {
            HttpSession mockHttpSession = mock(HttpSession.class);
            when(mockRequest.getSession()).thenReturn(mockHttpSession);
        }

        config.accept(mockRequest);
        return mockRequest;
    }

    private void mockAuthenticationInRequest(HttpServletRequest request) {
        when(request.getParameter("code")).thenReturn("some-code");
    }

    private void mockStateParamInRequest(HttpServletRequest request, String state) {
        when(request.getParameter("state")).thenReturn(state);
    }

    private void mockStateParamInSession(HttpSession session, String origin, String state) {
        when(session.getAttribute(SessionUtils.stateParameterAttributeKeyForIdp(origin))).thenReturn(state);
    }
}
