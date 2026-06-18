package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.csrf.CsrfException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Scenario tests for the multi-browser-tab concurrent external OAuth login problem.
 *
 * <h2>Background</h2>
 * UAA stores one {@code state} parameter per IDP in the HTTP session.  When a user
 * triggers the login flow in two browser tabs for the same IDP, the session ends up
 * holding only the most-recently generated state.  If the older tab's callback arrives
 * first, the state check fails.
 *
 * <h2>Scenarios covered</h2>
 * <ol>
 *   <li><b>Happy path</b> – a single tab completes login; state matches; filter chain continues.</li>
 *   <li><b>No session</b> – session has been destroyed (e.g. timeout); filter throws
 *       {@link org.springframework.web.HttpSessionRequiredException}.</li>
 *   <li><b>No state in session</b> – CSRF / replay attempt; filter throws
 *       {@link org.springframework.security.web.csrf.CsrfException}.</li>
 *   <li><b>No state in callback request</b> – malformed or tampered callback; filter throws
 *       {@link org.springframework.security.web.csrf.CsrfException}.</li>
 *   <li><b>Concurrent login (two tabs)</b> – both tabs started login; session holds the newer
 *       state; older tab's callback arrives with a stale state.  Filter MUST NOT throw; instead
 *       it sets {@code oauth_concurrent_login=true} in the session and redirects to
 *       {@code /oauth_error}, where the user sees a friendly message with a "Start a new login"
 *       link.</li>
 *   <li><b>Authentication failure</b> – state is valid but the IDP token exchange fails; filter
 *       stores an {@code oauth_error} in the session and redirects to {@code /oauth_error}.</li>
 * </ol>
 */
class ExternalOAuthConcurrentLoginScenarioTest {

    private static final String IDP_ORIGIN = "my-external-idp";
    private static final String STATE_FROM_TAB_1 = "state-generated-by-tab-1";
    private static final String STATE_FROM_TAB_2 = "state-generated-by-tab-2";

    private ExternalOAuthAuthenticationManager mockManager;
    private FilterChain mockChain;
    private ExternalOAuthAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        mockManager = mock(ExternalOAuthAuthenticationManager.class);
        mockChain = mock(FilterChain.class);
        filter = new ExternalOAuthAuthenticationFilter(mockManager, null);
    }

    // -------------------------------------------------------------------------
    // Scenario 1: happy path — single tab, state matches
    // -------------------------------------------------------------------------

    @Test
    void scenario_singleTab_stateMatches_filterChainContinues() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SessionUtils.stateParameterAttributeKeyForIdp(IDP_ORIGIN), STATE_FROM_TAB_1);

        HttpServletRequest req = buildRequest(STATE_FROM_TAB_1, session);
        HttpServletResponse res = mock(HttpServletResponse.class);

        filter.doFilter(req, res, mockChain);

        verify(mockChain).doFilter(req, res);
    }

    // -------------------------------------------------------------------------
    // Scenario 2: no session (timeout or session fixation protection)
    // -------------------------------------------------------------------------

    @Test
    void scenario_noSession_throwsHttpSessionRequiredException() {
        HttpServletRequest req = buildRequestWithNoSession(STATE_FROM_TAB_1);
        HttpServletResponse res = mock(HttpServletResponse.class);

        assertThatThrownBy(() -> filter.doFilter(req, res, mockChain))
                .isInstanceOf(org.springframework.web.HttpSessionRequiredException.class);
    }

    // -------------------------------------------------------------------------
    // Scenario 3: state missing from session (CSRF / replay)
    // -------------------------------------------------------------------------

    @Test
    void scenario_noStateInSession_throwsCsrfException() {
        MockHttpSession session = new MockHttpSession(); // empty session — no state stored

        HttpServletRequest req = buildRequest(STATE_FROM_TAB_1, session);
        HttpServletResponse res = mock(HttpServletResponse.class);

        assertThatThrownBy(() -> filter.doFilter(req, res, mockChain))
                .isInstanceOf(CsrfException.class);
    }

    // -------------------------------------------------------------------------
    // Scenario 4: state missing from callback request (malformed / tampered)
    // -------------------------------------------------------------------------

    @Test
    void scenario_noStateInCallback_throwsCsrfException() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SessionUtils.stateParameterAttributeKeyForIdp(IDP_ORIGIN), STATE_FROM_TAB_1);

        HttpServletRequest req = buildRequest(null, session);
        HttpServletResponse res = mock(HttpServletResponse.class);

        assertThatThrownBy(() -> filter.doFilter(req, res, mockChain))
                .isInstanceOf(CsrfException.class);
    }

    // -------------------------------------------------------------------------
    // Scenario 5: concurrent login — the key new scenario
    //
    //   Tab 1 starts  →  state_1 stored in session
    //   Tab 2 starts  →  state_2 OVERWRITES state_1 in session
    //   Tab 1 returns →  callback carries state_1, but session has state_2
    // -------------------------------------------------------------------------

    @Test
    void scenario_concurrentTabs_olderTabCallback_doesNotThrow() throws Exception {
        HttpServletRequest req = buildConcurrentLoginRequest();
        HttpServletResponse res = mock(HttpServletResponse.class);

        // Must NOT propagate an exception — the user should see a helpful error page instead
        filter.doFilter(req, res, mockChain);
    }

    @Test
    void scenario_concurrentTabs_olderTabCallback_filterChainIsNotContinued() throws Exception {
        HttpServletRequest req = buildConcurrentLoginRequest();
        HttpServletResponse res = mock(HttpServletResponse.class);

        filter.doFilter(req, res, mockChain);

        verify(mockChain, never()).doFilter(any(), any());
    }

    @Test
    void scenario_concurrentTabs_olderTabCallback_concurrentLoginFlagSetInSession() throws Exception {
        MockHttpSession session = sessionWithConcurrentLoginState();

        HttpServletRequest req = buildRequest(STATE_FROM_TAB_1, session);
        HttpServletResponse res = mock(HttpServletResponse.class);

        filter.doFilter(req, res, mockChain);

        assertThat(session.getAttribute("oauth_concurrent_login")).isEqualTo(Boolean.TRUE);
    }

    @Test
    void scenario_concurrentTabs_olderTabCallback_redirectsToOAuthErrorPage() throws Exception {
        MockHttpSession session = sessionWithConcurrentLoginState();

        HttpServletRequest req = buildRequest(STATE_FROM_TAB_1, session);
        HttpServletResponse res = mock(HttpServletResponse.class);

        filter.doFilter(req, res, mockChain);

        verify(res).sendRedirect("/uaa/oauth_error");
    }

    @Test
    void scenario_concurrentTabs_olderTabCallback_doesNotSetGenericOAuthError() throws Exception {
        MockHttpSession session = sessionWithConcurrentLoginState();

        HttpServletRequest req = buildRequest(STATE_FROM_TAB_1, session);
        HttpServletResponse res = mock(HttpServletResponse.class);

        filter.doFilter(req, res, mockChain);

        // The generic "There was an error..." oauth_error must NOT be set — the template uses
        // oauth_concurrent_login to show a specific, user-friendly message instead.
        assertThat(session.getAttribute("oauth_error")).isNull();
    }

    // -------------------------------------------------------------------------
    // Scenario 5b: mismatched state that UAA never issued (CSRF / tampering).
    //
    //   The session holds a valid state, the callback carries a different state that was never
    //   issued for this origin. This must still be treated as CSRF — NOT downgraded to the
    //   friendly concurrent-login redirect.
    // -------------------------------------------------------------------------

    @Test
    void scenario_mismatchedStateNeverIssued_throwsCsrfException() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SessionUtils.stateParameterAttributeKeyForIdp(IDP_ORIGIN), STATE_FROM_TAB_2);

        HttpServletRequest req = buildRequest("forged-state-from-attacker", session);
        HttpServletResponse res = mock(HttpServletResponse.class);

        assertThatThrownBy(() -> filter.doFilter(req, res, mockChain))
                .isInstanceOf(CsrfException.class);
    }

    // -------------------------------------------------------------------------
    // Scenario 6: authentication failure (valid state, but token exchange fails)
    // -------------------------------------------------------------------------

    @Test
    void scenario_authenticationFailure_storesErrorInSessionAndRedirects() throws Exception {
        when(mockManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("token exchange rejected by IDP"));

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SessionUtils.stateParameterAttributeKeyForIdp(IDP_ORIGIN), STATE_FROM_TAB_1);

        HttpServletRequest req = buildRequest(STATE_FROM_TAB_1, session);
        HttpServletResponse res = mock(HttpServletResponse.class);

        filter.doFilter(req, res, mockChain);

        assertThat((String) session.getAttribute("oauth_error"))
                .contains("token exchange rejected by IDP");
        verify(res).sendRedirect("/uaa/oauth_error");
        verify(mockChain, never()).doFilter(any(), any());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private HttpServletRequest buildConcurrentLoginRequest() {
        return buildRequest(STATE_FROM_TAB_1, sessionWithConcurrentLoginState());
    }

    /**
     * Builds a session in the state it would be in after tab 2 superseded tab 1: the session holds
     * tab 2's state and tab 1's (now stale, but UAA-issued) state is recorded as superseded.
     */
    private MockHttpSession sessionWithConcurrentLoginState() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SessionUtils.stateParameterAttributeKeyForIdp(IDP_ORIGIN), STATE_FROM_TAB_2);
        SessionUtils.recordSupersededState(session, IDP_ORIGIN, STATE_FROM_TAB_1);
        return session;
    }

    private HttpServletRequest buildRequest(String stateInCallback, MockHttpSession session) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getContextPath()).thenReturn("/uaa");
        when(req.getRequestURI()).thenReturn("/uaa/login/callback/" + IDP_ORIGIN);
        when(req.getServletPath()).thenReturn("login/callback/" + IDP_ORIGIN);
        when(req.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/" + IDP_ORIGIN));
        when(req.getParameter("code")).thenReturn("some-auth-code");
        when(req.getParameter("state")).thenReturn(stateInCallback);
        when(req.getSession()).thenReturn(session);
        when(req.getSession(false)).thenReturn(session);

        return req;
    }

    private HttpServletRequest buildRequestWithNoSession(String stateInCallback) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getContextPath()).thenReturn("/uaa");
        when(req.getRequestURI()).thenReturn("/uaa/login/callback/" + IDP_ORIGIN);
        when(req.getServletPath()).thenReturn("login/callback/" + IDP_ORIGIN);
        when(req.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/" + IDP_ORIGIN));
        when(req.getParameter("code")).thenReturn("some-auth-code");
        when(req.getParameter("state")).thenReturn(stateInCallback);
        when(req.getSession()).thenReturn(null);

        return req;
    }
}
