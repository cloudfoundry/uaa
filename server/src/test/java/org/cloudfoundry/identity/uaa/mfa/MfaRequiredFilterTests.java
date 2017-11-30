/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.HashSet;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.cloudfoundry.identity.uaa.mfa.MfaRequiredFilter.MfaNextStep.INVALID_AUTH;
import static org.cloudfoundry.identity.uaa.mfa.MfaRequiredFilter.MfaNextStep.MFA_COMPLETED;
import static org.cloudfoundry.identity.uaa.mfa.MfaRequiredFilter.MfaNextStep.MFA_IN_PROGRESS;
import static org.cloudfoundry.identity.uaa.mfa.MfaRequiredFilter.MfaNextStep.MFA_OK;
import static org.cloudfoundry.identity.uaa.mfa.MfaRequiredFilter.MfaNextStep.MFA_REQUIRED;
import static org.cloudfoundry.identity.uaa.mfa.MfaRequiredFilter.MfaNextStep.NOT_AUTHENTICATED;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class MfaRequiredFilterTests {

    private RequestCache requestCache;
    private MfaRequiredFilter filter;
    private MockHttpServletRequest request;
    private UsernamePasswordAuthenticationToken usernameAuthentication;
    private AnonymousAuthenticationToken anonymous;
    private UaaAuthentication authentication;
    private HttpServletResponse response;
    private FilterChain chain;

    @Before
    public void setup() throws Exception {
        requestCache = mock(RequestCache.class);
        filter = spy(
            new MfaRequiredFilter("/login/mfa/**",
                                  "/login/mfa/register",
                                  requestCache,
                                  "/login/mfa/completed")
        );
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
    }

    @After
    public void teardown() throws Exception {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    public void mfa_not_required() throws Exception {
        assertFalse(filter.mfaRequired());
    }

    @Test
    public void mfa_required() throws Exception {
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true);
        assertTrue(filter.mfaRequired());
    }

    @Test
    public void authentication_log_info_null() throws Exception {
        assertNull(filter.getAuthenticationLogInfo());
    }

    @Test
    public void authentication_log_info_uaa() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertThat(filter.getAuthenticationLogInfo(), containsString("fake-id"));
        assertThat(filter.getAuthenticationLogInfo(), containsString("fake-username"));
    }

    @Test
    public void authentication_log_info_unknown() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(usernameAuthentication);
        assertThat(filter.getAuthenticationLogInfo(), containsString("Unknown Auth=org.springframework.security.authentication.UsernamePasswordAuthenticationToken"));
        assertThat(filter.getAuthenticationLogInfo(), containsString("fake-principal"));
    }

    @Test
    public void next_step_not_authenticated() throws Exception {
        assertSame(NOT_AUTHENTICATED, filter.getNextStep(request));
    }

    @Test
    public void next_step_anonymous() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(anonymous);
        assertSame(NOT_AUTHENTICATED, filter.getNextStep(request));
    }

    @Test
    public void next_step_unknown_authentication() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(usernameAuthentication);
        assertSame(INVALID_AUTH, filter.getNextStep(request));
    }

    @Test
    public void next_step_mfa_not_needed() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_OK, filter.getNextStep(request));
    }

    @Test
    public void next_step_mfa_required() throws Exception {
        request.setServletPath("/");
        request.setPathInfo("oauth/authorize");
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_REQUIRED, filter.getNextStep(request));
    }

    @Test
    public void next_step_mfa_in_progress() throws Exception {
        request.setServletPath("/");
        request.setPathInfo("login/mfa/register");
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_IN_PROGRESS, filter.getNextStep(request));
    }

    @Test
    public void next_step_mfa_in_progress_when_completed_invoked() throws Exception {
        request.setServletPath("/");
        request.setPathInfo("login/mfa/completed");
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_IN_PROGRESS, filter.getNextStep(request));
    }

    @Test
    public void next_step_mfa_completed() throws Exception {
        request.setServletPath("/");
        request.setPathInfo("login/mfa/completed");
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true);
        authentication.getAuthenticationMethods().addAll(Arrays.asList("pwd", "mfa"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_COMPLETED, filter.getNextStep(request));
    }

    @Test
    public void next_step_mfa_in_play() throws Exception {
        request.setServletPath("/");
        request.setPathInfo("oauth/authorize");
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true);
        authentication.getAuthenticationMethods().addAll(Arrays.asList("pwd", "mfa"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertSame(MFA_OK, filter.getNextStep(request));
    }

    @Test
    public void send_redirect() throws Exception {
        request.setServletPath("/");
        request.setContextPath("/uaa");
        filter.sendRedirect("/login/mfa/register", request, response);
        verify(response, times(1)).sendRedirect("/uaa/login/mfa/register");
    }

    @Test
    public void do_filter_invalid_auth() throws Exception {
        when(filter.getNextStep(any(HttpServletRequest.class))).thenReturn(INVALID_AUTH);
        filter.doFilter(request, response, chain);
        verify(response, times(1)).sendError(401, "Invalid authentication object for UI operations.");
    }

    @Test
    public void do_filter_not_authenticated() throws Exception {
        when(filter.getNextStep(any(HttpServletRequest.class))).thenReturn(NOT_AUTHENTICATED);
        filter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verifyZeroInteractions(requestCache);
    }

    @Test
    public void do_filter_mfa_in_progress() throws Exception {
        when(filter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_IN_PROGRESS);
        filter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verifyZeroInteractions(requestCache);
    }

    @Test
    public void do_filter_mfa_ok() throws Exception {
        when(filter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_OK);
        filter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verifyZeroInteractions(requestCache);
    }

    @Test
    public void do_filter_mfa_completed_no_saved_request() throws Exception {
        request.setContextPath("/uaa");
        when(filter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_COMPLETED);
        filter.doFilter(request, response, chain);
        verify(requestCache, times(1)).getRequest(same(request), same(response));
        verify(filter, times(1)).sendRedirect(eq("/"), same(request), same(response));
    }

    @Test
    public void do_filter_mfa_completed_with_saved_request() throws Exception {
        SavedRequest savedRequest = mock(SavedRequest.class);
        String redirect = "http://localhost:8080/uaa/oauth/authorize";
        when(savedRequest.getRedirectUrl()).thenReturn(redirect);
        when(requestCache.getRequest(same(request), same(response))).thenReturn(savedRequest);
        request.setContextPath("/uaa");
        when(filter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_COMPLETED);
        filter.doFilter(request, response, chain);
        verify(requestCache, times(1)).getRequest(same(request), same(response));
        verify(filter, times(1)).sendRedirect(eq(redirect), same(request), same(response));

    }

    @Test
    public void do_filter_mfa_required() throws Exception {
        request.setContextPath("/uaa");
        when(filter.getNextStep(any(HttpServletRequest.class))).thenReturn(MFA_REQUIRED);
        filter.doFilter(request, response, chain);
        verify(requestCache, times(1)).saveRequest(same(request), same(response));
        verify(filter, times(1)).sendRedirect(eq("/login/mfa/register"), same(request), same(response));
    }

}