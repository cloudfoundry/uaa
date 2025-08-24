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

package org.cloudfoundry.identity.uaa.web;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

@Slf4j
public class UaaSavedRequestAwareAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    public static final String URI_OVERRIDE_ATTRIBUTE = "override.redirect_uri";
    public static final String FORM_REDIRECT_PARAMETER = "form_redirect_uri";

    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();

    public UaaSavedRequestAwareAuthenticationSuccessHandler() {
        requestCache.setMatchingRequestParameterName(null);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        SavedRequest savedRequest = this.requestCache.getRequest(request, response);
        if (savedRequest == null) {
            String relayState = UaaStringUtils.getCleanedUserControlString(request.getParameter(Saml2ParameterNames.RELAY_STATE), UaaStringUtils.EMPTY_STRING);
            if (UaaStringUtils.hasText(relayState) && UaaUrlUtils.isUrl(relayState)) {
                log.debug("Redirecting to relayState URI: {}", relayState);
                this.getRedirectStrategy().sendRedirect(request, response, relayState);
            } else {
                super.onAuthenticationSuccess(request, response, authentication);
            }
        } else {
            String targetUrlParameter = this.getTargetUrlParameter();
            if (!this.isAlwaysUseDefaultTargetUrl() && (targetUrlParameter == null || !UaaStringUtils.hasText(request.getParameter(targetUrlParameter)))) {
                this.clearAuthenticationAttributes(request);
                String targetUrl = savedRequest.getRedirectUrl();
                this.getRedirectStrategy().sendRedirect(request, response, targetUrl);
            } else {
                this.requestCache.removeRequest(request, response);
                super.onAuthenticationSuccess(request, response, authentication);
            }
        }
    }

    @Override
    public String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        Object redirectAttribute = request.getAttribute(URI_OVERRIDE_ATTRIBUTE);
        String redirectFormParam = request.getParameter(FORM_REDIRECT_PARAMETER);
        if (redirectAttribute != null) {
            log.debug("Returning redirectAttribute saved URI: {}", redirectAttribute);
            return (String) redirectAttribute;
        } else if (UaaUrlUtils.uriHasMatchingHost(redirectFormParam, request.getServerName())) {
            return redirectFormParam;
        } else {
            return super.determineTargetUrl(request, response);
        }
    }
}
