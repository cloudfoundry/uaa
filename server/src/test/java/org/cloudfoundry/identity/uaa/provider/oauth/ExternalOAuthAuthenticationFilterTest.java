package org.cloudfoundry.identity.uaa.provider.oauth;

import org.assertj.core.api.InstanceOfAssertFactories;
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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.ArrayDeque;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
        void itShouldCallTheNextFilter() throws Exception {
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
        void itCallsTheSuccessHandler() throws Exception {
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
        void itShouldNotCallTheNextFilter() throws Exception {
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
        void itThrowsIfNoSession() throws Exception {
            HttpServletRequest mockRequest = mockRedirectRequest(false, ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain)).asInstanceOf(InstanceOfAssertFactories.throwable(HttpSessionRequiredException.class));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itThrowsIfNoStateInSession() throws Exception {
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain)).asInstanceOf(InstanceOfAssertFactories.throwable(CsrfException.class));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itThrowsIfNoStateInRequest() throws Exception {
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain)).asInstanceOf(InstanceOfAssertFactories.throwable(CsrfException.class));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itThrowsCsrfExceptionIfStateInRequestButNoStateInSession() throws Exception {
            // No state in session (e.g. session expired or CSRF attack) → CsrfException propagates
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, OAUTH_STATE);
                // no state in session
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain))
                    .asInstanceOf(InstanceOfAssertFactories.throwable(CsrfException.class));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itThrowsCsrfExceptionIfStateIsMismatchedAndNotPreviouslyIssued() throws Exception {
            // Session holds a state, the request carries a different state that UAA never issued
            // (e.g. tampering / CSRF). It must NOT be downgraded to a concurrent-login redirect.
            HttpServletRequest mockRequest = mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, "forged-state-from-attacker");
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, OAUTH_STATE);
            });
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            assertThatThrownBy(() ->
                    externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain))
                    .asInstanceOf(InstanceOfAssertFactories.throwable(CsrfException.class));
            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }
    }

    /**
     * Scenario: user opens two browser tabs for the same external IDP login.
     * <p>
     * Tab 1 starts login → UAA generates state_1, stores it in the session, redirects to IDP.
     * Tab 2 starts login → UAA generates state_2, OVERWRITES state_1 in the session, redirects to IDP.
     * Tab 1 completes login → IDP callback arrives with state_1, but session now holds state_2.
     * <p>
     * Expected: UAA detects the concurrent login scenario, sets a session flag, and redirects
     * to the error page with a human-readable message and a "Start a new login" link.
     */
    @Nested
    @ExtendWith(PollutionPreventionExtension.class)
    class WhenConcurrentLoginAttemptDetected {

        private static final String STATE_FROM_TAB_1 = "state-generated-when-tab1-clicked-idp-link";
        private static final String STATE_FROM_TAB_2 = "state-generated-when-tab2-clicked-idp-link";

        @BeforeEach
        void setUp() {
            externalOAuthAuthenticationFilter = new ExternalOAuthAuthenticationFilter(externalOAuthAuthenticationManager, null);
        }

        @Test
        void itDoesNotPropagateAnException() throws Exception {
            HttpServletRequest mockRequest = buildConcurrentLoginRequest();
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            // Should NOT throw — the concurrent login case is handled internally
            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
        }

        @Test
        void itDoesNotContinueTheFilterChain() throws Exception {
            HttpServletRequest mockRequest = buildConcurrentLoginRequest();
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

            verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        }

        @Test
        void itSetsConcurrentLoginFlagInSession() throws Exception {
            HttpServletRequest mockRequest = buildConcurrentLoginRequest();
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

            verify(mockRequest.getSession()).setAttribute("oauth_concurrent_login", Boolean.TRUE);
        }

        @Test
        void itRedirectsToOAuthErrorPage() throws Exception {
            HttpServletRequest mockRequest = buildConcurrentLoginRequest();
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

            verify(mockResponse).sendRedirect("/uaa/oauth_error");
        }

        @Test
        void itDoesNotSetGenericOAuthErrorInSession() throws Exception {
            HttpServletRequest mockRequest = buildConcurrentLoginRequest();
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);

            externalOAuthAuthenticationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

            verify(mockRequest.getSession(), never()).setAttribute(org.mockito.ArgumentMatchers.eq("oauth_error"), any());
        }

        private HttpServletRequest buildConcurrentLoginRequest() {
            // Tab 2's state is in the session (it overwrote tab 1's state), and tab 1's state was
            // recorded as superseded when tab 2 started its login. Tab 1's callback arrives with
            // tab 1's (now stale, but UAA-issued) state.
            return mockRedirectRequest(ORIGIN_KEY, request -> {
                mockAuthenticationInRequest(request);
                mockStateParamInRequest(request, STATE_FROM_TAB_1);
                mockStateParamInSession(request.getSession(), ORIGIN_KEY, STATE_FROM_TAB_2);
                mockSupersededStatesInSession(request.getSession(), ORIGIN_KEY, STATE_FROM_TAB_1);
            });
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
        void itRedirects() throws Exception {
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
                throws Exception {
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

    private void mockSupersededStatesInSession(HttpSession session, String origin, String... states) {
        when(session.getAttribute(SessionUtils.supersededStateParameterAttributeKeyForIdp(origin)))
                .thenReturn(new ArrayDeque<>(List.of(states)));
    }
}
