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

import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UaaAuthenticationFailureHandler implements AuthenticationFailureHandler, LogoutHandler {
    private ExceptionMappingAuthenticationFailureHandler delegate;
    private CurrentUserCookieFactory currentUserCookieFactory;

    public UaaAuthenticationFailureHandler(ExceptionMappingAuthenticationFailureHandler delegate, CurrentUserCookieFactory currentUserCookieFactory) {
        this.delegate = delegate;
        this.currentUserCookieFactory = currentUserCookieFactory;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        addCookie(response);
        if(exception != null) {
            if (exception instanceof PasswordChangeRequiredException) {
                SessionUtils.setForcePasswordExpiredUser(request.getSession(),
                        ((PasswordChangeRequiredException) exception).getAuthentication());
            }
        }
        if (delegate!=null) {
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
