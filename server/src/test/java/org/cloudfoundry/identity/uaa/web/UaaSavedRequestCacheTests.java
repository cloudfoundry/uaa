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
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
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

public class UaaSavedRequestCacheTests {

    private UaaSavedRequestCache cache;
    private UaaSavedRequestCache spy;
    private MockHttpSession session;
    private MockHttpServletRequest request;
    private String redirectUri;

    @Before
    public void setup() {
        cache = new UaaSavedRequestCache();
        session = new MockHttpSession();
        request = new MockHttpServletRequest(POST.name(), "/login.do");
        redirectUri = "http://test";
        spy = spy(cache);
    }

    @After
    public void reset() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void creatingASavedRequestShouldParseParameters() {
        String url = "http://localhost:8080/?param1=value1&param1=value12&param2=value2";
        ClientRedirectSavedRequest saved = new ClientRedirectSavedRequest(request, url);
        assertNotNull(saved.getParameterMap());
        String[] param1s = saved.getParameterMap().get("param1");
        assertNotNull(param1s);
        assertArrayEquals(new String[] {"value1", "value12"}, param1s);

        param1s = saved.getParameterValues("param1");
        assertNotNull(param1s);
        assertArrayEquals(new String[] {"value1", "value12"}, param1s);

        assertArrayEquals(new String[] {"param1", "param2"}, saved.getParameterNames().toArray(new String[0]));

        String[] param2 = saved.getParameterMap().get("param2");
        assertNotNull(param2);
        assertArrayEquals(new String[] {"value2"}, param2);

        param2 = saved.getParameterValues("param2");
        assertNotNull(param2);
        assertArrayEquals(new String[] {"value2"}, param2);


    }

    @Test
    public void filter_saves_when_needed() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        request.setPathInfo("/login.do");
        request.setRequestURI("/login.do");
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        request.setServerName(new URL(redirectUri).getHost());
        assertTrue(cache.shouldSaveFormRedirectParameter(request));
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
    public void saveClientRedirect_On_Regular_Get() {
        request.setSession(session);
        request.setScheme("http");
        request.setServerName("localhost");
        request.setRequestURI("/test");
        request.setMethod(HttpMethod.GET.name());
        spy.saveRequest(request, new MockHttpServletResponse());
        verify(spy, times(1)).saveClientRedirect(request, "http://localhost/test");
    }


    @Test
    public void saveFormRedirectRequest_GET_Method() {
        request.setSession(session);
        request.setParameter(FORM_REDIRECT_PARAMETER, "http://login");
        request.setMethod(HttpMethod.GET.name());
        spy.saveRequest(request, new MockHttpServletResponse());
        verify(spy, never()).saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
    }


    @Test
    public void saveFormRedirectRequest() throws Exception {
        String redirectUri = "http://login";
        request.setSession(session);
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        request.setServerName(new URL(redirectUri).getHost());

        spy.saveRequest(request, new MockHttpServletResponse());
        verify(spy).saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
    }

    @Test
    public void do_not_save_form() {
        request.setSession(session);
        spy.saveRequest(request, new MockHttpServletResponse());
        verify(spy, never()).saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
    }

    @Test
    public void only_save_for_POST_calls() {
        request.setMethod(GET.name());
        assertFalse(cache.shouldSaveFormRedirectParameter(request));
        request.setPathInfo("/login.do");
        assertFalse(cache.shouldSaveFormRedirectParameter(request));
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        assertFalse(cache.shouldSaveFormRedirectParameter(request));
    }

    @Test
    public void should_save_condition_works() throws MalformedURLException {
        assertFalse(cache.shouldSaveFormRedirectParameter(request));

        request.setPathInfo("/login.do");
        assertFalse(cache.shouldSaveFormRedirectParameter(request));

        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        request.setServerName(new URL(redirectUri).getHost());
        assertTrue(cache.shouldSaveFormRedirectParameter(request));

        request.setSession(session);
        assertTrue(cache.shouldSaveFormRedirectParameter(request));

        SessionUtils.setSavedRequestSession(session, new ClientRedirectSavedRequest(request, redirectUri));
        assertFalse(cache.shouldSaveFormRedirectParameter(request));
    }

    @Test
    public void save_returns_correct_object() {
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        cache.saveClientRedirect(request, request.getParameter(FORM_REDIRECT_PARAMETER));
        HttpSession session = request.getSession(false);
        assertNotNull(session);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
        assertNotNull(savedRequest);
        assertEquals(redirectUri, savedRequest.getRedirectUrl());
        assertEquals(GET.name(), savedRequest.getMethod());
    }

    @Test
    public void saved_request_matcher() {
        String redirectUrl = "https://example.com/example?name=value";
        request.setScheme("https");
        request.setRequestURI("/example");
        request.setServerName("example.com");
        request.setQueryString("name=value");
        request.setServerPort(443);
        ClientRedirectSavedRequest saved = new ClientRedirectSavedRequest(request, redirectUrl);
        assertTrue(saved.doesRequestMatch(request, null));

        request.setQueryString("name=value&name2=value2");
        assertFalse(saved.doesRequestMatch(request, null));
        request.setQueryString("name=value");

        request = new MockHttpServletRequest(POST.name(), "/login.do");
        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUrl);
        assertTrue(saved.doesRequestMatch(request, null));

    }

    @Test
    public void unapprovedFormRedirectRequestDoesNotSave() throws IOException, ServletException {
        request.setPathInfo("/login.do");
        request.setRequestURI("/login.do");
        request.setMethod(HttpMethod.POST.name());
        request.setParameter(FORM_REDIRECT_PARAMETER, "http://test.com");
        request.setServerName("not-test.com");

        spy.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));

        verify(spy, never()).saveClientRedirect(any(HttpServletRequest.class), anyString());
    }
}