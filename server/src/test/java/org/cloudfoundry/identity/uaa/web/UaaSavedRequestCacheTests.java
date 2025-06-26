/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache.ClientRedirectSavedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.SavedRequest;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

class UaaSavedRequestCacheTests {

    private UaaSavedRequestCache cache;
    private UaaSavedRequestCache spy;
    private MockHttpSession session;
    private MockHttpServletRequest request;
    private String redirectUri;

    @BeforeEach
    void setup() {
        cache = new UaaSavedRequestCache();
        session = new MockHttpSession();
        request = new MockHttpServletRequest(POST.name(), "/login.do");
        redirectUri = "http://test";
        spy = spy(cache);
    }

    @AfterEach
    void reset() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void creatingASavedRequestShouldParseParameters() {
        String url = "http://localhost:8080/?param1=value1&param1=value12&param2=value2";
        ClientRedirectSavedRequest saved = new ClientRedirectSavedRequest(request, url);
        assertThat(saved.getParameterMap()).isNotNull();
        String[] param1s = saved.getParameterMap().get("param1");
        assertThat(param1s)
                .containsExactly(new String[]{"value1", "value12"});

        param1s = saved.getParameterValues("param1");
        assertThat(param1s)
                .containsExactly(new String[]{"value1", "value12"});

        assertThat(saved.getParameterNames().toArray(new String[0])).containsExactly(new String[]{"param1", "param2"});

        String[] param2 = saved.getParameterMap().get("param2");
        assertThat(param2)
                .containsExactly(new String[]{"value2"});

        param2 = saved.getParameterValues("param2");
        assertThat(param2)
                .containsExactly(new String[]{"value2"});
    }

    @Test
    void filter_saves_when_needed() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        request.setPathInfo("/login.do");
        request.setRequestURI("/login.do");
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        request.setServerName(URI.create(redirectUri).toURL().getHost());
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isTrue();
        ServletResponse response = new MockHttpServletResponse();

        spy.doFilter(request, response, chain);
        verify(spy, times(1)).shouldSaveFormRedirectParameter(request);
        verify(spy, times(1)).saveClientRedirect(any(), anyString());

        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        spy.doFilter(request, response, chain);
        verify(spy, times(2)).shouldSaveFormRedirectParameter(request);
        verify(spy, times(1)).saveClientRedirect(any(), anyString());
        verify(chain, times(2)).doFilter(request, response);

    }

    @Test
    void saveClientRedirect_On_Regular_Get() {
        request.setSession(session);
        request.setScheme("http");
        request.setServerName("localhost");
        request.setRequestURI("/test");
        request.setMethod(HttpMethod.GET.name());
        spy.saveRequest(request, new MockHttpServletResponse());
        verify(spy, times(1)).saveClientRedirect(request, "http://localhost/test");
    }

    @Test
    void saveFormRedirectRequest_GET_Method() {
        request.setSession(session);
        request.setParameter(FORM_REDIRECT_PARAMETER, "http://login");
        request.setMethod(HttpMethod.GET.name());
        spy.saveRequest(request, new MockHttpServletResponse());
        verify(spy, never()).saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
    }

    @Test
    void saveFormRedirectRequest() throws Exception {
        String redirectUri = "http://login";
        request.setSession(session);
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        request.setServerName(URI.create(redirectUri).toURL().getHost());

        spy.saveRequest(request, new MockHttpServletResponse());
        verify(spy).saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
    }

    @Test
    void do_not_save_form() {
        request.setSession(session);
        spy.saveRequest(request, new MockHttpServletResponse());
        verify(spy, never()).saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
    }

    @Test
    void only_save_for_POST_calls() {
        request.setMethod(GET.name());
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isFalse();
        request.setPathInfo("/login.do");
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isFalse();
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isFalse();
    }

    @Test
    void should_save_condition_works() throws MalformedURLException {
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isFalse();

        request.setPathInfo("/login.do");
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isFalse();

        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        request.setServerName(URI.create(redirectUri).toURL().getHost());
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isTrue();

        request.setSession(session);
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isTrue();

        SessionUtils.setSavedRequestSession(session, new ClientRedirectSavedRequest(request, redirectUri));
        assertThat(cache.shouldSaveFormRedirectParameter(request)).isFalse();
    }

    @Test
    void save_returns_correct_object() {
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        cache.saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
        HttpSession session = request.getSession(false);
        assertThat(session).isNotNull();
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
        assertThat(savedRequest).isNotNull();
        assertThat(savedRequest.getRedirectUrl()).isEqualTo(redirectUri);
        assertThat(savedRequest.getMethod()).isEqualTo(GET.name());
    }

    @Test
    void saved_request_matcher() {
        String redirectUrl = "https://example.com/example?name=value";
        request.setScheme("https");
        request.setRequestURI("/example");
        request.setServerName("example.com");
        request.setQueryString("name=value");
        request.setServerPort(443);
        ClientRedirectSavedRequest saved = new ClientRedirectSavedRequest(request, redirectUrl);
        assertThat(saved.doesRequestMatch(request, null)).isTrue();

        request.setQueryString("name=value&name2=value2");
        assertThat(saved.doesRequestMatch(request, null)).isFalse();
        request.setQueryString("name=value");

        request = new MockHttpServletRequest(POST.name(), "/login.do");
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUrl);
        assertThat(saved.doesRequestMatch(request, null)).isTrue();
    }

    @Test
    void unapprovedFormRedirectRequestDoesNotSave() throws IOException, ServletException {
        request.setPathInfo("/login.do");
        request.setRequestURI("/login.do");
        request.setMethod(HttpMethod.POST.name());
        request.setParameter(FORM_REDIRECT_PARAMETER, "http://test.com");
        request.setServerName("not-test.com");

        spy.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));
        verify(spy, never()).saveClientRedirect(any(HttpServletRequest.class), anyString());
    }
}
