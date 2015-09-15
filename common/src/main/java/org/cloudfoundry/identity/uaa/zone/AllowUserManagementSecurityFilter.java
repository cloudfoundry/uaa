/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class AllowUserManagementSecurityFilter extends OncePerRequestFilter {

    private final IdentityProviderProvisioning identityProviderProvisioning;

    private static String regex = "";
    static {
        // scim user endpoints
        regex = "^/Users.*";

        // ui controllers
        regex += "|^/create_account";
        regex += "|^/create_account.do";
        regex += "|^/accounts/email_sent";
        regex += "|^/verify_user";
        regex += "|^/change_email";
        regex += "|^/change_email.do";
        regex += "|^/verify_email";
        regex += "|^/change_password";
        regex += "|^/change_password.do";
        regex += "|^/forgot_password";
        regex += "|^/forgot_password.do";
        regex += "|^/email_sent";
        regex += "|^/reset_password";
        regex += "|^/reset_password.do";
    }

    private Pattern pattern = Pattern.compile(regex);
    private List<String> methods = Arrays.asList("GET", "POST", "PUT", "DELETE");

    public AllowUserManagementSecurityFilter(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (matches(request)) {
            IdentityProvider idp = identityProviderProvisioning.retrieveByOrigin(Origin.UAA, IdentityZoneHolder.get().getId());
            if (!idp.isAllowInternalUserManagement()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Internal User Creation is currently disabled. External User Store is in use.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean matches(HttpServletRequest request) {
        return pattern.matcher(getUri(request)).matches() && methods.contains(request.getMethod());
    }

    private String getUri(HttpServletRequest request) {
        if (request.getContextPath() != null && request.getContextPath().length() > 0) {
            return request.getServletPath();
        }
        return request.getRequestURI();
    }
}
