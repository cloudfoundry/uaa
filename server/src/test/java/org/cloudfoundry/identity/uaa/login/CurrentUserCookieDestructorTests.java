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

package org.cloudfoundry.identity.uaa.login;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.Cookie;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class CurrentUserCookieDestructorTests {

    private AuthenticationFailureHandler failureHandler;
    private MockHttpServletResponse response;
    private MockHttpServletRequest request;
    private CurrentUserCookieDestructor destructor;

    @Before
    public void setup() throws Exception {
        failureHandler = mock(AuthenticationFailureHandler.class);
        destructor = new CurrentUserCookieDestructor(failureHandler);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void onAuthenticationFailure() throws Exception {
        AuthenticationException exception = mock(AuthenticationException.class);
        destructor.onAuthenticationFailure(request, response, exception);
        verify(failureHandler, times(1)).onAuthenticationFailure(same(request), same(response), same(exception));
        validateCookie();
    }

    @Test
    public void onAuthenticationFailure_Without_Delegate() throws Exception {
        AuthenticationException exception = mock(AuthenticationException.class);
        destructor = new CurrentUserCookieDestructor(null);
        destructor.onAuthenticationFailure(request, response, exception);
        validateCookie();
    }

    public void validateCookie() {
        Cookie cookie = response.getCookie("Current-User");
        assertNotNull(cookie);
        assertEquals(0, cookie.getMaxAge());
        assertFalse(cookie.isHttpOnly());
    }

    @Test
    public void logout() throws Exception {
        destructor.logout(request, response, mock(Authentication.class));
        validateCookie();
    }

}