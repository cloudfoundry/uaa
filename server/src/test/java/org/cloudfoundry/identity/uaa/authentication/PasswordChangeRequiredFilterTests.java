/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import javax.servlet.FilterChain;
import java.util.HashSet;

import org.cloudfoundry.identity.uaa.oauth.InteractionRequiredException;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import static java.util.Collections.emptyList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

public class PasswordChangeRequiredFilterTests {
    private PasswordChangeRequiredFilter filter;
    private MockHttpSession session;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AuthenticationEntryPoint entryPoint;
    private FilterChain chain;

    @Before
    public void setup() {
        UaaAuthentication authentication = new UaaAuthentication(
                new UaaPrincipal("fake-id", "fake-username", "email@email.com", "origin", "", "uaa"),
                emptyList(),
                null
        );
        authentication.setAuthenticationMethods(new HashSet<>());
        entryPoint = mock(AuthenticationEntryPoint.class);
        chain = mock(FilterChain.class);
        filter = new PasswordChangeRequiredFilter(
            entryPoint
        );
        session = new MockHttpSession();
        SessionUtils.setPasswordChangeRequired(session, false);
        request = new MockHttpServletRequest();
        request.setSession(session);
        response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @After
    public void teardown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void password_change_required() throws Exception {
        SessionUtils.setPasswordChangeRequired(session, true);
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(chain);
        verify(entryPoint, times(1)).commence(same(request), same(response), any(InteractionRequiredException.class));
    }

    @Test
    public void password_change_not_required() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(entryPoint);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void no_authentication() throws Exception {
        SecurityContextHolder.clearContext();
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(entryPoint);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }
}