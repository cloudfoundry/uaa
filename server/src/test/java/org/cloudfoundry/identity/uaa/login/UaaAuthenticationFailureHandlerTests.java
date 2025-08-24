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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.internal.verification.VerificationModeFactory.times;

import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;

class UaaAuthenticationFailureHandlerTests {

    private ExceptionMappingAuthenticationFailureHandler failureHandler;
    private MockHttpServletResponse response;
    private MockHttpServletRequest request;
    private UaaAuthenticationFailureHandler uaaAuthenticationFailureHandler;
    private CurrentUserCookieFactory cookieFactory;

    @BeforeEach
    void setup() {
        failureHandler = new ExceptionMappingAuthenticationFailureHandler();
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException", "/force_password_change");
        failureHandler.setExceptionMappings(errorMap);
        failureHandler = spy(failureHandler);
        cookieFactory = new CurrentUserCookieFactory(1234, false);
        uaaAuthenticationFailureHandler = new UaaAuthenticationFailureHandler(failureHandler, cookieFactory);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void onAuthenticationFailure() throws Exception {
        AuthenticationException exception = mock(AuthenticationException.class);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        verify(failureHandler, times(1)).onAuthenticationFailure(same(request), same(response), same(exception));
        validateCookie();
    }

    @Test
    void onAuthenticationFailure_Without_Delegate() throws Exception {
        AuthenticationException exception = mock(AuthenticationException.class);
        uaaAuthenticationFailureHandler = new UaaAuthenticationFailureHandler(null, cookieFactory);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        validateCookie();
    }

    @Test
    void logout() {
        uaaAuthenticationFailureHandler.logout(request, response, mock(Authentication.class));
        validateCookie();
    }

    @Test
    void onAuthenticationFailure_ForcePasswordChange() throws IOException, ServletException {
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        PasswordChangeRequiredException exception = new PasswordChangeRequiredException(uaaAuthentication, "mock");
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        UaaAuthentication uaaAuthenticationFromSession = SessionUtils.getForcePasswordExpiredUser(request.getSession());
        assertThat(uaaAuthenticationFromSession)
                .isNotNull()
                .isEqualTo(uaaAuthentication);
        validateCookie();
        assertThat(response.getRedirectedUrl()).isEqualTo("/force_password_change");
    }

    @Test
    void redirectUrls() throws ServletException, IOException {
        var handler = new UaaAuthenticationFailureHandler(cookieFactory);

        var response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new AccountNotVerifiedException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=account_not_verified");

        response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new AuthenticationPolicyRejectionException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=account_locked");

        response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new AccountNotPreCreatedException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=account_not_precreated");

        response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new PasswordChangeRequiredException(mock(UaaAuthentication.class), "test"));
        assertThat(response.getRedirectedUrl()).isEqualTo("/force_password_change");

        response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new BadCredentialsException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=login_failure");
    }

    private void validateCookie() {
        Cookie cookie = response.getCookie("Current-User");
        assertThat(cookie).isNotNull();
        assertThat(cookie.getMaxAge()).isZero();
        assertThat(cookie.isHttpOnly()).isFalse();
    }

}