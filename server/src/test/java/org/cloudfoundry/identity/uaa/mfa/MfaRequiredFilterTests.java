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

package org.cloudfoundry.identity.uaa.mfa;

import javax.servlet.FilterChain;
import java.util.Arrays;
import java.util.HashSet;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class MfaRequiredFilterTests {
    private UaaAuthentication authentication;
    private MfaRequiredFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MfaChecker mfaChecker;
    private AuthenticationEntryPoint entryPoint;
    private FilterChain chain;

    @Before
    public void setup() {
        authentication = new UaaAuthentication(
            new UaaPrincipal("fake-id", "fake-username", "email@email.com", "origin", "", "uaa"),
            emptyList(),
            null
        );
        authentication.setAuthenticationMethods(new HashSet<>());
        mfaChecker = mock(MfaChecker.class);
        entryPoint = mock(AuthenticationEntryPoint.class);
        chain = mock(FilterChain.class);
        filter = new MfaRequiredFilter(
            mfaChecker,
            entryPoint
        );
        when(mfaChecker.isMfaEnabled(any(IdentityZone.class))).thenReturn(true);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @After
    public void teardown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void mfa_required() throws Exception {
        assertTrue(filter.isMfaRequiredAndMissing());
        filter.doFilter(request, response, chain);
        Mockito.verify(chain, never()).doFilter(same(request), same(response));
    }

    @Test
    public void authentication_missing() {
        SecurityContextHolder.clearContext();
        assertFalse(filter.isMfaRequiredAndMissing());
    }

    @Test
    public void anonymous_authentication() {
        SecurityContextHolder.getContext().setAuthentication(mock(AnonymousAuthenticationToken.class));
        assertFalse(filter.isMfaRequiredAndMissing());
    }

    @Test
    public void unknown_authentication() {
        SecurityContextHolder.getContext().setAuthentication(mock(UsernamePasswordAuthenticationToken.class));
        assertFalse(filter.isMfaRequiredAndMissing());
    }

    @Test
    public void mfa_present() throws Exception {
        authentication.setAuthenticationMethods(new HashSet<>(Arrays.asList("pwd","mfa")));
        assertFalse(filter.isMfaRequiredAndMissing());
        filter.doFilter(request, response, chain);
        Mockito.verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void mfa_not_enabled() {
        when(mfaChecker.isMfaEnabled(any(IdentityZone.class))).thenReturn(false);
        assertFalse(filter.isMfaRequiredAndMissing());
    }


}