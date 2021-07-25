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

import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class UaaAuthenticationFailureHandlerTests {

    private ExceptionMappingAuthenticationFailureHandler failureHandler;
    private MockHttpServletResponse response;
    private MockHttpServletRequest request;
    private UaaAuthenticationFailureHandler uaaAuthenticationFailureHandler;
    private CurrentUserCookieFactory cookieFactory;

    @Before
    public void setup() {
        failureHandler = new ExceptionMappingAuthenticationFailureHandler();
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException", "/force_password_change");
        errorMap.put("org.cloudfoundry.identity.uaa.authentication.MfaAuthenticationRequiredException", "/login/mfa/register");
        failureHandler.setExceptionMappings(errorMap);
        failureHandler = spy(failureHandler);
        cookieFactory = new CurrentUserCookieFactory(1234, false);
        uaaAuthenticationFailureHandler = new UaaAuthenticationFailureHandler(failureHandler, cookieFactory);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void onAuthenticationFailure() throws Exception {
        AuthenticationException exception = mock(AuthenticationException.class);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        verify(failureHandler, times(1)).onAuthenticationFailure(same(request), same(response), same(exception));
        validateCookie();
    }

    @Test
    public void onAuthenticationFailure_Without_Delegate() throws Exception {
        AuthenticationException exception = mock(AuthenticationException.class);
        uaaAuthenticationFailureHandler = new UaaAuthenticationFailureHandler(null, cookieFactory);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        validateCookie();
    }

    @Test
    public void logout() {
        uaaAuthenticationFailureHandler.logout(request, response, mock(Authentication.class));
        validateCookie();
    }

    @Test
    public void onAuthenticationFailure_ForcePasswordChange() throws IOException, ServletException {
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        PasswordChangeRequiredException exception = new PasswordChangeRequiredException(uaaAuthentication, "mock");
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        UaaAuthentication uaaAuthenticationFromSession = SessionUtils.getForcePasswordExpiredUser(request.getSession());
        assertNotNull(uaaAuthenticationFromSession);
        assertEquals(uaaAuthentication, uaaAuthenticationFromSession);
        validateCookie();
        assertEquals("/force_password_change", response.getRedirectedUrl());
    }

    private void validateCookie() {
        Cookie cookie = response.getCookie("Current-User");
        assertNotNull(cookie);
        assertEquals(0, cookie.getMaxAge());
        assertFalse(cookie.isHttpOnly());
    }

}