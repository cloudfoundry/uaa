/*
 * ******************************************************************************
 *  *     Cloud Foundry
 *  *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *  *
 *  *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  *     You may not use this product except in compliance with the License.
 *  *
 *  *     This product includes a number of subcomponents with
 *  *     separate copyright notices and license terms. Your use of these
 *  *     subcomponents is subject to the terms and conditions of the
 *  *     subcomponent's license, as noted in the LICENSE file.
 *  ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import lombok.Getter;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Date;
import java.util.Objects;

public class SessionResetFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(SessionResetFilter.class);

    private final RedirectStrategy strategy;
    private final IdentityZoneManager identityZoneManager;
    @Getter
    private final String redirectUrl;
    private final UaaUserDatabase userDatabase;

    public SessionResetFilter(RedirectStrategy strategy, IdentityZoneManager identityZoneManager, String redirectUrl, UaaUserDatabase userDatabase) {
        this.strategy = strategy;
        this.identityZoneManager = identityZoneManager;
        this.redirectUrl = redirectUrl;
        this.userDatabase = userDatabase;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        SecurityContext context = SecurityContextHolder.getContext();
        if (context != null && context.getAuthentication() != null && context.getAuthentication() instanceof UaaAuthentication authentication) {
            // zone check
            if (!Objects.equals(identityZoneManager.getCurrentIdentityZoneId(), authentication.getPrincipal().getZoneId())) {
                handleRedirect(request, response);
                return;
            }

            // is authenticated UAA user
            if (authentication.isAuthenticated() &&
                    OriginKeys.UAA.equals(authentication.getPrincipal().getOrigin()) &&
                    null != request.getSession(false)) {

                boolean redirect = false;
                String userId = authentication.getPrincipal().getId();
                try {
                    logger.debug("Evaluating user-id for session reset:{}", userId);
                    UaaUserPrototype user = userDatabase.retrieveUserPrototypeById(userId);
                    Date lastModified;
                    if ((lastModified = user.getPasswordLastModified()) != null) {
                        long lastAuthTime = authentication.getAuthenticatedTime();
                        long passwordModTime = lastModified.getTime();
                        //if the password has changed after authentication time
                        if (hasPasswordChangedAfterAuthentication(lastAuthTime, passwordModTime)) {
                            logger.debug("Resetting user session for user ID: {} Auth Time: {} Password Change Time: {}", userId, lastAuthTime, passwordModTime);
                            redirect = true;
                        }
                    }
                } catch (UsernameNotFoundException x) {
                    logger.info("Authenticated user [{}] was not found in DB.", userId);
                    redirect = true;
                }
                if (redirect) {
                    handleRedirect(request, response);
                    return;
                }
            }
        }
        filterChain.doFilter(request, response);
    }

    protected boolean hasPasswordChangedAfterAuthentication(long lastAuthTime, long passwordModTime) {
        return passwordModTime > lastAuthTime;
    }

    protected void handleRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        strategy.sendRedirect(request, response, getRedirectUrl());
    }
}
