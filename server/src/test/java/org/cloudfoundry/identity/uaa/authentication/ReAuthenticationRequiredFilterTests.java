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

package org.cloudfoundry.identity.uaa.authentication;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.*;

public class ReAuthenticationRequiredFilterTests {

    private ReAuthenticationRequiredFilter filter;
    private UaaAuthentication authentication;
    private MockHttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;

    @Before
    public void setup() {
        filter = new ReAuthenticationRequiredFilter();
        authentication = mock(UaaAuthentication.class);
        request = new MockHttpServletRequest();
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        request.setContextPath("");
    }

    @After
    public void clear () {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void request_with_prompt_login() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setParameter("client_id", "testclient");
        request.setParameter("prompt", "login");
        request.setParameter("scope", "openid");
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(same(request), same(response));
        // verify that the redirect is happening and the redirect url does not contain the prompt parameter
        verify(response, times(1)).sendRedirect(matches("^((?!prompt).)*$"));
    }

    @Test
    public void request_with_prompt_none() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setParameter("prompt", "none");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void request_with_max_age_redirect_expected() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.getAuthenticatedTime()).thenReturn(System.currentTimeMillis() - 2000);
        request.setParameter("client_id", "testclient");
        request.setParameter("max_age", "1");
        request.setParameter("scope", "openid");
        filter.doFilterInternal(request, response, chain);
        verify(chain, never()).doFilter(same(request), same(response));
        // verify that the redirect was happening and the url does not contain the max_age parameter
        verify(response, times(1)).sendRedirect(matches("^((?!max_age).)*$"));
    }

    @Test
    public void request_with_max_age_redirect_not_expected() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(authentication.getAuthenticatedTime()).thenReturn(System.currentTimeMillis());
        request.setParameter("client_id", "testclient");
        request.setParameter("max_age", "1");
        request.setParameter("scope", "openid");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void request_without_prompt_and_max_age() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setParameter("client_id", "testclient");
        request.setParameter("scope", "openid");
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(response, never()).sendRedirect(anyString());
    }
}