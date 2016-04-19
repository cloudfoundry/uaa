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
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class DisableUserManagementSecurityFilter extends OncePerRequestFilter {

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

    public DisableUserManagementSecurityFilter(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, final HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (matches(request)) {
            IdentityProvider idp = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
            boolean isDisableInternalUserManagement = false;
            UaaIdentityProviderDefinition config = ObjectUtils.castInstance(idp.getConfig(), UaaIdentityProviderDefinition.class);
            if (config != null) {
                isDisableInternalUserManagement = config.isDisableInternalUserManagement();
            }
            if (isDisableInternalUserManagement) {
                ExceptionReportHttpMessageConverter converter = new ExceptionReportHttpMessageConverter();
                response.setStatus(403);
                converter.write(new ExceptionReport(new InternalUserManagementDisabledException("Internal User Creation is currently disabled. External User Store is in use.")),
                    MediaType.APPLICATION_JSON, new ServletServerHttpResponse(response));
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
