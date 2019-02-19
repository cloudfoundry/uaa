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
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

public class PasswordChangeRequiredFilter extends OncePerRequestFilter {

    private final AuthenticationEntryPoint entryPoint;

    public PasswordChangeRequiredFilter(AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (needsPasswordReset()) {
            entryPoint.commence(request,
                                response,
                                new PasswordChangeRequiredException(
                                    (UaaAuthentication) getContext().getAuthentication(),
                                    "password reset is required"
                                )
            );
        } else {
            //pass through
            filterChain.doFilter(request, response);
        }
    }

    protected boolean needsPasswordReset() {
        Authentication authentication = getContext().getAuthentication();
        return authentication != null &&
            authentication instanceof UaaAuthentication &&
            ((UaaAuthentication)authentication).isRequiresPasswordChange() &&
            authentication.isAuthenticated();
    }
}
