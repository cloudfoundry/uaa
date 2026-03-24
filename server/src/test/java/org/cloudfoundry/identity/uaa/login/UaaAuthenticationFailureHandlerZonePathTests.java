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
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

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
import org.cloudfoundry.identity.uaa.util.ZoneRequestPathMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;

@EnabledIfZonePathsEnabled
class UaaAuthenticationFailureHandlerZonePathTests {

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

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void onAuthenticationFailure(ZoneRequestPathMode mode) throws Exception {
        mode.applyRequestPath(request, "/login.do");
        AuthenticationException exception = mock(AuthenticationException.class);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        verify(failureHandler, times(1)).onAuthenticationFailure(same(request), same(response), same(exception));
        validateCookie(mode);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void onAuthenticationFailure_Without_Delegate(ZoneRequestPathMode mode) throws Exception {
        mode.applyRequestPath(request, "/login.do");
        uaaAuthenticationFailureHandler = new UaaAuthenticationFailureHandler(null, cookieFactory);
        AuthenticationException exception = mock(AuthenticationException.class);
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        validateCookie(mode);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void logout(ZoneRequestPathMode mode) {
        mode.applyRequestPath(request, "/login");
        uaaAuthenticationFailureHandler.logout(request, response, mock(Authentication.class));
        validateCookie(mode);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void onAuthenticationFailure_ForcePasswordChange(ZoneRequestPathMode mode) throws IOException, ServletException {
        mode.applyRequestPath(request, "/login.do");
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        PasswordChangeRequiredException exception = new PasswordChangeRequiredException(uaaAuthentication, "mock");
        uaaAuthenticationFailureHandler.onAuthenticationFailure(request, response, exception);
        UaaAuthentication uaaAuthenticationFromSession = SessionUtils.getForcePasswordExpiredUser(request.getSession());
        assertThat(uaaAuthenticationFromSession)
                .isNotNull()
                .isEqualTo(uaaAuthentication);
        validateCookie(mode);
        assertThat(response.getRedirectedUrl()).isEqualTo(mode.redirectPrefix() + "/force_password_change");
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void redirectUrls(ZoneRequestPathMode mode) throws ServletException, IOException {
        var handler = new UaaAuthenticationFailureHandler(cookieFactory);
        String redirectPrefix = mode.redirectPrefix();

        mode.applyRequestPath(request, "/login.do");

        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new AccountNotVerifiedException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/login?error=account_not_verified");

        response = new MockHttpServletResponse();
        mode.applyRequestPath(request, "/login.do");
        handler.onAuthenticationFailure(request, response, new AuthenticationPolicyRejectionException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/login?error=account_locked");

        response = new MockHttpServletResponse();
        mode.applyRequestPath(request, "/login.do");
        handler.onAuthenticationFailure(request, response, new AccountNotPreCreatedException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/login?error=account_not_precreated");

        response = new MockHttpServletResponse();
        mode.applyRequestPath(request, "/force_password_change");
        handler.onAuthenticationFailure(request, response, new PasswordChangeRequiredException(mock(UaaAuthentication.class), "test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/force_password_change");

        response = new MockHttpServletResponse();
        mode.applyRequestPath(request, "/login.do");
        handler.onAuthenticationFailure(request, response, new BadCredentialsException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/login?error=login_failure");
        validateCookie(response, mode);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void redirectUrlsWithContextPath(ZoneRequestPathMode mode) throws ServletException, IOException {
        var handler = new UaaAuthenticationFailureHandler(cookieFactory);
        request.setContextPath("/uaa");
        String redirectPrefix = "/uaa" + mode.redirectPrefix();

        mode.applyRequestPath(request, "/login.do");

        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(request, response, new AccountNotVerifiedException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/login?error=account_not_verified");

        response = new MockHttpServletResponse();
        mode.applyRequestPath(request, "/login.do");
        handler.onAuthenticationFailure(request, response, new AuthenticationPolicyRejectionException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/login?error=account_locked");

        response = new MockHttpServletResponse();
        mode.applyRequestPath(request, "/login.do");
        handler.onAuthenticationFailure(request, response, new AccountNotPreCreatedException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/login?error=account_not_precreated");

        response = new MockHttpServletResponse();
        mode.applyRequestPath(request, "/force_password_change");
        handler.onAuthenticationFailure(request, response, new PasswordChangeRequiredException(mock(UaaAuthentication.class), "test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/force_password_change");

        response = new MockHttpServletResponse();
        mode.applyRequestPath(request, "/login.do");
        handler.onAuthenticationFailure(request, response, new BadCredentialsException("test"));
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectPrefix + "/login?error=login_failure");
        validateCookie(response, mode);
    }

    private void validateCookie(ZoneRequestPathMode mode) {
        validateCookie(response, mode);
    }

    private void validateCookie(MockHttpServletResponse response, ZoneRequestPathMode mode) {
        Cookie cookie = response.getCookie("Current-User");
        assertThat(cookie).isNotNull();
        assertThat(cookie.getMaxAge()).isZero();
        assertThat(cookie.isHttpOnly()).isFalse();
        // CurrentUserCookieFactory sets path to "/" for all requests (no zone-scoping in production).
        assertThat(cookie.getPath()).isEqualTo("/");
    }

}
