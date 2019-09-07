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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Date;

public class SessionResetFilter extends OncePerRequestFilter {

    private static Logger logger = LoggerFactory.getLogger(SessionResetFilter.class);

    private final RedirectStrategy strategy;
    private final String redirectUrl;
    private final UaaUserDatabase userDatabase;

    public SessionResetFilter(RedirectStrategy strategy, String redirectUrl, UaaUserDatabase userDatabase) {
        this.strategy = strategy;
        this.redirectUrl = redirectUrl;
        this.userDatabase = userDatabase;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        SecurityContext context = SecurityContextHolder.getContext();
        if (context!=null && context.getAuthentication()!=null && context.getAuthentication() instanceof UaaAuthentication) {
            UaaAuthentication authentication = (UaaAuthentication)context.getAuthentication();
            if (authentication.isAuthenticated() &&
                OriginKeys.UAA.equals(authentication.getPrincipal().getOrigin()) &&
                null != request.getSession(false)) {

                boolean redirect = false;
                String userId = authentication.getPrincipal().getId();
                try {
                    logger.debug("Evaluating user-id for session reset:"+userId);
                    UaaUser user = userDatabase.retrieveUserById(userId);
                    Date lastModified;
                    if ((lastModified = user.getPasswordLastModified()) != null) {
                        long lastAuthTime = authentication.getAuthenticatedTime();
                        long passwordModTime = lastModified.getTime();
                        //if the password has changed after authentication time
                        if (hasPasswordChangedAfterAuthentication(lastAuthTime, passwordModTime)) {
                            logger.debug(String.format("Resetting user session for user ID: %s Auth Time: %s Password Change Time: %s",userId, lastAuthTime, passwordModTime));
                            redirect = true;
                        }
                    }
                } catch (UsernameNotFoundException x) {
                    logger.info("Authenticated user ["+userId+"] was not found in DB.");
                    redirect = true;
                }
                if (redirect) {
                    handleRedirect(request, response);
                    return;
                }
            }
        }
        filterChain.doFilter(request,response);
    }

    protected boolean hasPasswordChangedAfterAuthentication(long lastAuthTime, long passwordModTime) {
        return passwordModTime > lastAuthTime;
    }

    protected void handleRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session!=null) {
            session.invalidate();
        }
        strategy.sendRedirect(request, response, getRedirectUrl());
    }
}
