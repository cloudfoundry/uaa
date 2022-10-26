/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
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

package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MfaUiRequiredFilter extends GenericFilterBean {
    private static Logger logger = LoggerFactory.getLogger(MfaUiRequiredFilter.class);

    private final AntPathRequestMatcher inProgressMatcher;
    private final AntPathRequestMatcher completedMatcher;
    private final AntPathRequestMatcher logoutMatcher;
    private final String redirect;
    private final RequestCache cache;
    private final MfaChecker checker;

    public MfaUiRequiredFilter(String urlFilter,
                               String redirect,
                               RequestCache cache,
                               String mfaCompleteUrl,
                               AntPathRequestMatcher logoutMatcher,
                               MfaChecker checker) {
        inProgressMatcher = new AntPathRequestMatcher(urlFilter);
        this.redirect = redirect;
        this.cache = cache;
        this.completedMatcher = new AntPathRequestMatcher(mfaCompleteUrl);
        this.checker = checker;
        this.logoutMatcher = logoutMatcher;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        switch (getNextStep(request)) {
            case INVALID_AUTH:
                logger.debug("Unrecognized authentication object:" + getAuthenticationLogInfo());
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid authentication object for UI operations.");
                break;
            case NOT_AUTHENTICATED:
            case MFA_IN_PROGRESS:
            case MFA_NOT_REQUIRED:
            case MFA_OK:
                chain.doFilter(request, response);
                break;
            case MFA_REQUIRED:
                logger.debug("Request requires MFA, redirecting to MFA flow for " + getAuthenticationLogInfo());
                if (cache.getRequest(request, response) == null) {
                    cache.saveRequest(request, response);
                }
                sendRedirect(redirect, request, response);
                break;
            case MFA_COMPLETED:
                logger.debug("MFA has been completed for " + getAuthenticationLogInfo());
                SavedRequest savedRequest = cache.getRequest(request, response);
                if (savedRequest != null) {
                    logger.debug("Redirecting request to " + savedRequest.getRedirectUrl());
                    sendRedirect(savedRequest.getRedirectUrl(), request, response);
                } else {
                    logger.debug("Redirecting request to /");
                    sendRedirect("/", request, response);
                }
                break;
        }
    }

    protected String getAuthenticationLogInfo() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a == null) {
            return null;
        }
        StringBuilder result = new StringBuilder();
        if (a instanceof UaaAuthentication) {
            UaaPrincipal principal = ((UaaAuthentication) a).getPrincipal();
            result
              .append("Username:")
              .append(principal.getName())
              .append(" User-ID:")
              .append(principal.getId());
        } else {
            result
                    .append("Unknown Auth=")
                    .append(a)
                    .append(" Principal=")
                    .append(a.getPrincipal());
        }
        return result.toString();
    }

    public enum MfaNextStep {
        NOT_AUTHENTICATED,
        MFA_IN_PROGRESS,
        MFA_REQUIRED,
        MFA_OK,
        MFA_NOT_REQUIRED,
        MFA_COMPLETED,
        INVALID_AUTH
    }

    protected MfaNextStep getNextStep(HttpServletRequest request) {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a == null || a instanceof AnonymousAuthenticationToken) {
            return MfaNextStep.NOT_AUTHENTICATED;
        }
        if (!(a instanceof UaaAuthentication)) {
            return MfaNextStep.INVALID_AUTH;
        }
        UaaAuthentication uaaAuth = (UaaAuthentication) a;
        if (!mfaRequired(uaaAuth.getPrincipal().getOrigin()) || logoutInProgress(request)) {
            return MfaNextStep.MFA_NOT_REQUIRED;
        }

        if (completedMatcher.matches(request) && uaaAuth.getAuthenticationMethods().contains("mfa")) {
            return MfaNextStep.MFA_COMPLETED;
        }
        if (inProgressMatcher.matches(request) && !uaaAuth.getAuthenticationMethods().contains("mfa")) {
            return MfaNextStep.MFA_IN_PROGRESS;
        }
        if (!inProgressMatcher.matches(request) && !uaaAuth.getAuthenticationMethods().contains("mfa")) {
            return MfaNextStep.MFA_REQUIRED;
        }
        if (uaaAuth.getAuthenticationMethods().contains("mfa")) {
            return MfaNextStep.MFA_OK;
        } else {
            return MfaNextStep.INVALID_AUTH;
        }
    }

    protected void sendRedirect(String redirectUrl, HttpServletRequest request, HttpServletResponse response) throws IOException {
        StringBuilder url = new StringBuilder(
          redirectUrl.startsWith("/") ? request.getContextPath() : ""
        );
        url.append(redirectUrl);
        response.sendRedirect(url.toString());
    }

    protected boolean mfaRequired(String origin) {
        return checker.isMfaEnabled(IdentityZoneHolder.get()) && checker.isRequired(IdentityZoneHolder.get(), origin);
    }

    private boolean logoutInProgress(HttpServletRequest request) {
        return logoutMatcher.matches(request);
    }
}
