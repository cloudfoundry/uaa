/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.security;


import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

public class IsUserSelfCheck {

    public boolean isSelf(HttpServletRequest request, int pathParameterIndex) {
        String pathInfo = UaaUrlUtils.getRequestPath(request);
        if (!StringUtils.hasText(pathInfo)) {
            return false;
        }

        String idFromUrl = extractIdFromUrl(pathParameterIndex, pathInfo);
        if (idFromUrl==null) {
            return false;
        }

        String idFromAuth = extractIdFromAuthentication(SecurityContextHolder.getContext().getAuthentication());
        if (idFromAuth==null) {
            return false;
        }

        return idFromAuth.equals(idFromUrl);
    }

    protected String extractIdFromAuthentication(Authentication authentication) {
        if (authentication==null) {
            return null;
        }
        if (authentication.getPrincipal() instanceof UaaPrincipal) {
            return ((UaaPrincipal)authentication.getPrincipal()).getId();
        }
        if (authentication instanceof OAuth2Authentication) {
            OAuth2Authentication a = (OAuth2Authentication)authentication;
            if (a.isClientOnly()) {
                return null;
            } else {
                if (a.getUserAuthentication().getPrincipal() instanceof UaaPrincipal) {
                    return ((UaaPrincipal)a.getUserAuthentication().getPrincipal()).getId();
                }
            }
        }
        return null;
    }

    protected String extractIdFromUrl(int pathParameterIndex, String pathInfo) {
        return UaaUrlUtils.extractPathVariableFromUrl(pathParameterIndex, pathInfo);
    }

}
