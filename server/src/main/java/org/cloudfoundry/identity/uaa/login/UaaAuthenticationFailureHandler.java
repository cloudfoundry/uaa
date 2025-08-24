/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
public class UaaAuthenticationFailureHandler implements AuthenticationFailureHandler, LogoutHandler {
    private final ExceptionMappingAuthenticationFailureHandler delegate;
    private final CurrentUserCookieFactory currentUserCookieFactory;

    @Autowired
    public UaaAuthenticationFailureHandler(CurrentUserCookieFactory currentUserCookieFactory) {
        this(defaultDelegateFailureHandler(), currentUserCookieFactory);
    }

    private static ExceptionMappingAuthenticationFailureHandler defaultDelegateFailureHandler() {
        var handler = new ExceptionMappingAuthenticationFailureHandler();
        handler.setExceptionMappings(
                Map.of(
                        AccountNotVerifiedException.class.getName(), "/login?error=account_not_verified",
                        AuthenticationPolicyRejectionException.class.getName(), "/login?error=account_locked",
                        AccountNotPreCreatedException.class.getName(), "/login?error=account_not_precreated",
                        PasswordChangeRequiredException.class.getName(), "/force_password_change"
                )
        );
        handler.setDefaultFailureUrl("/login?error=login_failure");
        return handler;
    }

    public UaaAuthenticationFailureHandler(ExceptionMappingAuthenticationFailureHandler delegate, CurrentUserCookieFactory currentUserCookieFactory) {
        this.delegate = delegate;
        this.currentUserCookieFactory = currentUserCookieFactory;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        addCookie(response);
        if (exception instanceof PasswordChangeRequiredException passwordChangeRequiredException) {
            SessionUtils.setForcePasswordExpiredUser(request.getSession(),
                    passwordChangeRequiredException.getAuthentication());
        }

        if (delegate != null) {
            delegate.onAuthenticationFailure(request, response, exception);
        }
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        addCookie(response);
    }

    private void addCookie(HttpServletResponse response) {
        Cookie clearCurrentUserCookie = currentUserCookieFactory.getNullCookie();
        response.addCookie(clearCurrentUserCookie);
    }
}
