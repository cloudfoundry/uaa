package org.cloudfoundry.identity.uaa.mfa;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.HashSet;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.cloudfoundry.identity.uaa.mfa.MfaUiRequiredFilter.MfaNextStep.INVALID_AUTH;
import static org.cloudfoundry.identity.uaa.mfa.MfaUiRequiredFilter.MfaNextStep.MFA_COMPLETED;
import static org.cloudfoundry.identity.uaa.mfa.MfaUiRequiredFilter.MfaNextStep.MFA_IN_PROGRESS;
import static org.cloudfoundry.identity.uaa.mfa.MfaUiRequiredFilter.MfaNextStep.MFA_NOT_REQUIRED;
import static org.cloudfoundry.identity.uaa.mfa.MfaUiRequiredFilter.MfaNextStep.MFA_OK;
import static org.cloudfoundry.identity.uaa.mfa.MfaUiRequiredFilter.MfaNextStep.MFA_REQUIRED;
import static org.cloudfoundry.identity.uaa.mfa.MfaUiRequiredFilter.MfaNextStep.NOT_AUTHENTICATED;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class MfaUiRequiredFilterTests {

    private RequestCache requestCache;
    private MfaUiRequiredFilter spyFilter;
    private MockHttpServletRequest request;
    private UsernamePasswordAuthenticationToken usernameAuthentication;
    private AnonymousAuthenticationToken anonymous;
    private UaaAuthentication authentication;
    private HttpServletResponse response;
    private FilterChain chain;
    private MfaUiRequiredFilter filter;
    private AntPathRequestMatcher logoutMatcher;
    private IdentityZone mfaEnabledZone;

    @BeforeEach
    void setup() {
        requestCache = mock(RequestCache.class);
        logoutMatcher = new AntPathRequestMatcher("/logout.do");
        filter = new MfaUiRequiredFilter("/login/mfa/**",
                                         "/login/mfa/register",
                                         requestCache,
                                         "/login/mfa/completed",
                                         logoutMatcher,
                                         new MfaChecker(mock(IdentityZoneProvisioning.class)));
        spyFilter = spy(filter);
        request = new MockHttpServletRequest();
        usernameAuthentication = new UsernamePasswordAuthenticationToken("fake-principal","fake-credentials");
        anonymous = new AnonymousAuthenticationToken("fake-key", "fake-principal", singletonList(new SimpleGrantedAuthority("test")));
        authentication = new UaaAuthentication(
            new UaaPrincipal("fake-id", "fake-username", "email@email.com", "origin", "", "uaa"),
            emptyList(),
            null
        );
        authentication.setAuthenticationMethods(new HashSet<>());
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        mfaEnabledZone = new IdentityZone();
        mfaEnabledZone.getConfig().getMfaConfig().setEnabled(true);
        mfaEnabledZone.getConfig().getMfaConfig().setIdentityProviders(Lists.newArrayList("origin"));
    }

    @AfterEach
    void teardown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void authentication_log_info_null() {
        assertNull(spyFilter.getAuthenticationLogInfo());
    }

    @Test
    void authentication_log_info_uaa() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertThat(spyFilter.getAuthenticationLogInfo(), containsString("fake-id"));
        assertThat(spyFilter.getAuthenticationLogInfo(), containsString("fake-username"));
    }

    @Test
    void authentication_log_info_unknown() {
        SecurityContextHolder.getContext().setAuthentication(usernameAuthentication);
        assertThat(spyFilter.getAuthenticationLogInfo(), containsString("Unknown Auth=UsernamePasswordAuthenticationToken"));
        assertThat(spyFilter.getAuthenticationLogInfo(), containsString("fake-principal"));
    }

    @Test
    void next_step_not_authenticated() {
        assertSame(NOT_AUTHENTICATED, spyFilter.getNextStep(request));
    }

    @Test
    void next_step_mfa_not_needed_when_origin_key_does_not_match_valid_identity_provider() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        IdentityZone zone = new IdentityZone();
        zone.getConfig().getMfaConfig().setIdentityProviders(Lists.newArrayList("uaa", "ldap"));
        zone.getConfig().getMfaConfig().setEnabled(true);
        IdentityZoneHolder.set(zone);
        assertThat(spyFilter.getNextStep(request), is(MFA_NOT_REQUIRED));
    }

    @Test
    void next_step_mfa_needed_when_origin_key_matches_valid_identity_provider() {
        UaaAuthentication auth = new UaaAuthentication(
          new UaaPrincipal("fake-id", "fake-username", "email@email.com", "ldap", "", "uaa"),
          emptyList(),
          null
        );
        auth.setAuthenticationMethods(new HashSet<>());
        SecurityContextHolder.getContext().setAuthentication(auth);
        IdentityZone zone = new IdentityZone();
        zone.getConfig().getMfaConfig().setIdentityProviders(Lists.newArrayList("uaa", "ldap"));
        zone.getConfig().getMfaConfig().setEnabled(true);

        IdentityZoneHolder.set(zone);
        assertThat(spyFilter.getNextStep(request), is(MFA_REQUIRED));
    }

    @Test
    void next_step_anonymous() {
        SecurityContextHolder.getContext().setAuthentication(anonymous);
        assertSame(NOT_AUTHENTICATED, spyFilter.getNextStep(request));
    }

    @Test
    void next_step_unknown_authentication() {
        SecurityContextHolder.getContext().setAuthentication(usernameAuthentication);
        assertSame(INVALID_AUTH, spyFilter.getNextStep(request));
    }

    @Test
    void next_step_mfa_not_needed() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_NOT_REQUIRED, spyFilter.getNextStep(request));
    }

    @Test
    void next_step_mfa_required() {
        request.setServletPath("/");
        request.setPathInfo("oauth/authorize");

        IdentityZoneHolder.set(mfaEnabledZone);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_REQUIRED, spyFilter.getNextStep(request));
    }

    @Test
    void next_step_mfa_in_progress() {
        request.setServletPath("/");
        request.setPathInfo("login/mfa/register");

        IdentityZoneHolder.set(mfaEnabledZone);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_IN_PROGRESS, spyFilter.getNextStep(request));
    }

    @Test
    void next_step_mfa_in_progress_when_completed_invoked() {
        request.setServletPath("/");
        request.setPathInfo("login/mfa/completed");

        IdentityZoneHolder.set(mfaEnabledZone);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_IN_PROGRESS, spyFilter.getNextStep(request));
    }

    @Test
    void next_step_mfa_completed() {
        request.setServletPath("/");
        request.setPathInfo("login/mfa/completed");

        IdentityZoneHolder.set(mfaEnabledZone);

        authentication.getAuthenticationMethods().addAll(Arrays.asList("pwd", "mfa"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_COMPLETED, spyFilter.getNextStep(request));
    }

    @Test
    void next_step_mfa_in_play() {
        request.setServletPath("/");
        request.setPathInfo("oauth/authorize");

        IdentityZoneHolder.set(mfaEnabledZone);

        authentication.getAuthenticationMethods().addAll(Arrays.asList("pwd", "mfa"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_OK, spyFilter.getNextStep(request));
    }

    @Test
    void send_redirect() throws Exception {
        request.setServletPath("/");
        request.setContextPath("/uaa");
        spyFilter.sendRedirect("/login/mfa/register", request, response);
        verify(response, times(1)).sendRedirect("/uaa/login/mfa/register");
    }

    @Test
    void do_filter_invalid_auth() throws Exception {
        when(spyFilter.getNextStep(any(HttpServletRequest.class))).thenReturn(INVALID_AUTH);
        spyFilter.doFilter(request, response, chain);
        verify(response, times(1)).sendError(401, "Invalid authentication object for UI operations.");
    }

    @Test
    void do_filter_not_authenticated() throws Exception {
        when(spyFilter.getNextStep(any(HttpServletRequest.class))).thenReturn(NOT_AUTHENTICATED);
        spyFilter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verifyNoInteractions(requestCache);
    }

    @Test
    void do_filter_mfa_in_progress() throws Exception {
        when(spyFilter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_IN_PROGRESS);
        spyFilter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verifyNoInteractions(requestCache);
    }

    @Test
    void do_filter_mfa_ok() throws Exception {
        when(spyFilter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_OK);
        spyFilter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verifyNoInteractions(requestCache);
    }

    @Test
    void do_filter_mfa_completed_no_saved_request() throws Exception {
        request.setContextPath("/uaa");
        when(spyFilter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_COMPLETED);
        spyFilter.doFilter(request, response, chain);
        verify(requestCache, times(1)).getRequest(same(request), same(response));
        verify(spyFilter, times(1)).sendRedirect(eq("/"), same(request), same(response));
    }

    @Test
    void do_filter_mfa_completed_with_saved_request() throws Exception {
        SavedRequest savedRequest = mock(SavedRequest.class);
        String redirect = "http://localhost:8080/uaa/oauth/authorize";
        when(savedRequest.getRedirectUrl()).thenReturn(redirect);
        when(requestCache.getRequest(same(request), same(response))).thenReturn(savedRequest);
        request.setContextPath("/uaa");
        when(spyFilter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_COMPLETED);
        spyFilter.doFilter(request, response, chain);
        verify(requestCache, times(1)).getRequest(same(request), same(response));
        verify(spyFilter, times(1)).sendRedirect(eq(redirect), same(request), same(response));

    }

    @Test
    void do_filter_mfa_required() throws Exception {
        request.setContextPath("/uaa");
        when(spyFilter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_REQUIRED);
        spyFilter.doFilter(request, response, chain);
        verify(requestCache, times(1)).saveRequest(same(request), same(response));
        verify(spyFilter, times(1)).sendRedirect(eq("/login/mfa/register"), same(request), same(response));
    }

}