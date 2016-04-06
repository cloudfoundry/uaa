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
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

public class DisableInternalUserManagementFilter extends OncePerRequestFilter {

    public static final String DISABLE_INTERNAL_USER_MANAGEMENT = "disableInternalUserManagement";
    private final IdentityProviderProvisioning identityProviderProvisioning;

    private static String regex = "^/login|^/Users.*";

    private Pattern pattern = Pattern.compile(regex);

    public DisableInternalUserManagementFilter(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (matches(request)) {
            IdentityProvider idp = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
            boolean isDisableInternalUserManagement = false;
            UaaIdentityProviderDefinition config = ObjectUtils.castInstance(idp.getConfig(), UaaIdentityProviderDefinition.class);
            if (config != null) {
                isDisableInternalUserManagement = config.isDisableInternalUserManagement();
            }
            request.setAttribute(DISABLE_INTERNAL_USER_MANAGEMENT, isDisableInternalUserManagement);
        }

        filterChain.doFilter(request, response);
    }

    private boolean matches(HttpServletRequest request) {
        if (request.getContextPath() != null && request.getContextPath().length() > 0) {
            return pattern.matcher(request.getServletPath()).matches();
        }
        return pattern.matcher(request.getRequestURI()).matches();
    }
}
