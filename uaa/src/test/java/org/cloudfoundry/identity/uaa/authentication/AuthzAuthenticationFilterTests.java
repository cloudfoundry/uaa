/*******************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthzAuthenticationFilterTests {

    @Test
    public void authenticatesValidUser() throws Exception {

        String msg = "{ \"username\":\"marissa\", \"password\":\"koala\"}";

        AuthenticationManager am = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(am.authenticate(any(AuthzAuthenticationRequest.class))).thenReturn(result);
        AuthzAuthenticationFilter filter = new AuthzAuthenticationFilter(am);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/authorize");
        request.setParameter("credentials", msg);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

    }


    @Test
    public void password_expired_fails_authentication() throws Exception {

        AuthenticationManager am = mock(AuthenticationManager.class);
        UaaAuthentication result = mock(UaaAuthentication.class);
        when(am.authenticate(any(AuthzAuthenticationRequest.class))).thenReturn(result);

        when(result.isAuthenticated()).thenReturn(true);
        when(result.isRequiresPasswordChange()).thenReturn(true);

        AuthzAuthenticationFilter filter = new AuthzAuthenticationFilter(am);
        AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(entryPoint);
        filter.setParameterNames(Arrays.asList("username", "password"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/authorize");
        request.setParameter("username", "marissa");
        request.setParameter("password", "anything");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        ArgumentCaptor<AuthenticationException> captor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(entryPoint, times(1)).commence(same(request), same(response), captor.capture());

        assertEquals(1, captor.getAllValues().size());
        assertEquals(PasswordChangeRequiredException.class, captor.getValue().getClass());
        assertEquals("password change required", captor.getValue().getMessage());
        assertSame(result, ((PasswordChangeRequiredException) captor.getValue()).getAuthentication());

    }
}
