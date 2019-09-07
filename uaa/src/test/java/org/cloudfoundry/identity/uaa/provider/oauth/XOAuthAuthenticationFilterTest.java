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


import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

import static java.util.Collections.EMPTY_LIST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class XOAuthAuthenticationFilterTest {

    private AccountSavingAuthenticationSuccessHandler successHandler = mock(AccountSavingAuthenticationSuccessHandler.class);

    @Before
    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testShouldAuthenticate() {
        XOAuthAuthenticationFilter filter = spy(new XOAuthAuthenticationFilter(mock(XOAuthAuthenticationManager.class), successHandler));
        MockHttpServletRequest request = new MockHttpServletRequest();
        testShouldAuthenticate(filter, request, "code", "value");
        testShouldAuthenticate(filter, request, "id_token", "value");
        testShouldAuthenticate(filter, request, "access_token", "value");
    }

    public void testShouldAuthenticate(XOAuthAuthenticationFilter filter,
                                       MockHttpServletRequest request,
                                       String pname,
                                       String pvalue) {
        assertFalse(filter.containsCredentials(request));
        request.setParameter(pname, pvalue);
        assertTrue(filter.containsCredentials(request));
        request.removeParameter(pname);
        assertFalse(filter.containsCredentials(request));
    }

    @Test
    public void getIdTokenInResponse() throws Exception {
        XOAuthAuthenticationManager xOAuthAuthenticationManager = mock(XOAuthAuthenticationManager.class);
        XOAuthAuthenticationFilter filter = spy(new XOAuthAuthenticationFilter(xOAuthAuthenticationManager, successHandler));

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
        when(request.getServletPath()).thenReturn("/login/callback/the_origin");
        when(request.getParameter("id_token")).thenReturn("the_id_token");
        when(request.getParameter("access_token")).thenReturn("the_access_token");
        when(request.getParameter("code")).thenReturn("the_code");

        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("id", "username", "email@email.com", OriginKeys.UAA, null, IdentityZoneHolder.get().getId()), EMPTY_LIST, new UaaAuthenticationDetails(request));
        Mockito.when(xOAuthAuthenticationManager.authenticate(any())).thenReturn(authentication);

        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);

        ArgumentCaptor<XOAuthCodeToken> captor = ArgumentCaptor.forClass(XOAuthCodeToken.class);
        verify(xOAuthAuthenticationManager).authenticate(captor.capture());
        verify(chain).doFilter(request, response);

        XOAuthCodeToken xoAuthCodeToken = captor.getValue();
        assertEquals("the_access_token", xoAuthCodeToken.getAccessToken());
        assertEquals("the_id_token", xoAuthCodeToken.getIdToken());
        assertEquals("the_code", xoAuthCodeToken.getCode());
        assertEquals("the_origin", xoAuthCodeToken.getOrigin());
        assertEquals("http://localhost/uaa/login/callback/the_origin", xoAuthCodeToken.getRedirectUrl());
        assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void getXOAuthCodeTokenFromRequest() throws Exception {
        XOAuthAuthenticationManager xOAuthAuthenticationManager = mock(XOAuthAuthenticationManager.class);

        XOAuthAuthenticationFilter filter = new XOAuthAuthenticationFilter(xOAuthAuthenticationManager, successHandler);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
        when(request.getServletPath()).thenReturn("/login/callback/the_origin");
        when(request.getParameter("code")).thenReturn("the_code");

        UaaAuthentication authentication = new UaaAuthentication(new UaaPrincipal("id", "username", "email@email.com", OriginKeys.UAA, null, IdentityZoneHolder.get().getId()), EMPTY_LIST, new UaaAuthenticationDetails(request));
        Mockito.when(xOAuthAuthenticationManager.authenticate(any())).thenReturn(authentication);

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
        assertNull(xoAuthCodeToken.getIdToken());
        assertNull(xoAuthCodeToken.getAccessToken());

    }

    @Test
    public void redirectsToErrorPageInCaseOfException() throws Exception {

        XOAuthAuthenticationManager xOAuthAuthenticationManager = mock(XOAuthAuthenticationManager.class);
        XOAuthAuthenticationFilter filter = new XOAuthAuthenticationFilter(xOAuthAuthenticationManager, successHandler);

        HttpServletRequest request = mock(HttpServletRequest.class);
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
        when(request.getServletPath()).thenReturn("/login/callback/the_origin");
        when(request.getParameter("code")).thenReturn("the_code");

        Mockito.doThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "error from oauth server")).when(xOAuthAuthenticationManager).authenticate(any());
        filter.doFilter(request, response, chain);
        Assert.assertThat(response.getHeader("Location"), Matchers.containsString(request.getContextPath() + "/oauth_error?error=There+was+an+error+when+authenticating+against+the+external+identity+provider%3A"));
    }
}
