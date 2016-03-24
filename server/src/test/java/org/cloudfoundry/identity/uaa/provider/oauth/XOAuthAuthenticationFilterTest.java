/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.provider.oauth;


import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class XOAuthAuthenticationFilterTest {

    @Test
    public void getXOAuthCodeTokenFromRequest() throws Exception {
        XOAuthAuthenticationManager xOAuthAuthenticationManager = Mockito.mock(XOAuthAuthenticationManager.class);
        XOAuthAuthenticationFilter filter = new XOAuthAuthenticationFilter(xOAuthAuthenticationManager);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
        when(request.getServletPath()).thenReturn("/login/callback/the_origin");
        when(request.getParameter("code")).thenReturn("the_code");

        MockAuthentication authentication = new MockAuthentication();
        Mockito.when(xOAuthAuthenticationManager.authenticate(anyObject())).thenReturn(authentication);

        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);

        ArgumentCaptor<XOAuthCodeToken> captor = ArgumentCaptor.forClass(XOAuthCodeToken.class);
        verify(xOAuthAuthenticationManager).authenticate(captor.capture());
        verify(chain).doFilter(request, response);

        XOAuthCodeToken xoAuthCodeToken = captor.getValue();
        assertEquals("the_code", xoAuthCodeToken.getCode());
        assertEquals("the_origin", xoAuthCodeToken.getOrigin());
        assertEquals("http://localhost/uaa/login/callback/the_origin", xoAuthCodeToken.getRedirectUrl());
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void redirectsToErrorPageInCaseOfException() throws Exception {

        XOAuthAuthenticationManager xOAuthAuthenticationManager = Mockito.mock(XOAuthAuthenticationManager.class);
        XOAuthAuthenticationFilter filter = new XOAuthAuthenticationFilter(xOAuthAuthenticationManager);

        HttpServletRequest request = mock(HttpServletRequest.class);
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
        when(request.getServletPath()).thenReturn("/login/callback/the_origin");
        when(request.getParameter("code")).thenReturn("the_code");

        Mockito.doThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "error from oauth server")).when(xOAuthAuthenticationManager).authenticate(anyObject());
        filter.doFilter(request, response, chain);
        Assert.assertThat(response.getHeader("Location"), Matchers.containsString(request.getContextPath() + "/oauth_error?error="));
    }
}
