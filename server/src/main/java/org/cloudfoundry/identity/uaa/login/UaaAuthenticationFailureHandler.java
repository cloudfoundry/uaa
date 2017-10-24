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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.MfaAuthenticationRequiredException;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.cloudfoundry.identity.uaa.login.ForcePasswordChangeController.FORCE_PASSWORD_EXPIRED_USER;
import static org.cloudfoundry.identity.uaa.login.TotpEndpoint.MFA_VALIDATE_USER;

public class UaaAuthenticationFailureHandler implements AuthenticationFailureHandler, LogoutHandler {
    private AuthenticationFailureHandler delegate;

    public UaaAuthenticationFailureHandler(AuthenticationFailureHandler delegate) {
        this.delegate = delegate;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        if(exception != null) {
            if (exception instanceof PasswordChangeRequiredException) {
                request.getSession().setAttribute(FORCE_PASSWORD_EXPIRED_USER, ((PasswordChangeRequiredException) exception).getAuthentication());
                addCookie(response, request.getContextPath());
                response.sendRedirect(request.getContextPath() + "/force_password_change");
                return;
            }
            if (exception instanceof MfaAuthenticationRequiredException) {
                request.getSession().setAttribute(MFA_VALIDATE_USER, ((MfaAuthenticationRequiredException) exception).getAuthentication());
                addCookie(response, request.getContextPath());
                response.sendRedirect(request.getContextPath() + "/login/mfa/register");
                return;
            }
        }
        addCookie(response, request.getContextPath());
        if (delegate!=null) {
            delegate.onAuthenticationFailure(request, response, exception);
        }
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        addCookie(response, request.getContextPath());
    }

    private void addCookie(HttpServletResponse response, String contextPath) {
        Cookie currentUserCookie = new Cookie("Current-User", null);
        currentUserCookie.setHttpOnly(false);
        currentUserCookie.setMaxAge(0);
        currentUserCookie.setPath(contextPath);
        response.addCookie(currentUserCookie);
    }
}
