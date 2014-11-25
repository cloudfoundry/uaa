/*
 * ******************************************************************************
 *      Cloud Foundry 
 *      Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Authentication filter translating a generic Authentication into a
 * UsernamePasswordAuthenticationToken.
 * 
 * @author Dave Syer
 * 
 */
public class ChainedAuthenticationManager implements AuthenticationManager {

    protected final Log logger = LogFactory.getLog(getClass());

    private final AuthenticationManager[] delegates;

    /**
     * @param delegate
     */
    public ChainedAuthenticationManager(AuthenticationManager delegate) {
        super();
        this.delegates = new AuthenticationManager[] {delegate};
    }

    public ChainedAuthenticationManager(AuthenticationManager delegate1, AuthenticationManager delegate2) {
        super();
        this.delegates = new AuthenticationManager[] {delegate1, delegate2};
    }

    public ChainedAuthenticationManager(AuthenticationManager[] delegates) {
        super();
        this.delegates = delegates;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationManager#
     * authenticate(org.springframework.security.core.Authentication)
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication == null) {
            return authentication;
        }
        UsernamePasswordAuthenticationToken output = null;
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            output = (UsernamePasswordAuthenticationToken) authentication;
        } else {
            output = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(),
                            authentication.getAuthorities());
            output.setAuthenticated(authentication.isAuthenticated());
            output.setDetails(authentication.getDetails());
        }
        boolean authenticated = false;
        Authentication auth = null;
        AuthenticationException lastException = null;
        for (int i=0; i<delegates.length && (!authenticated); i++) {
            try {
                if (logger.isDebugEnabled()) {
                    logger.debug("Attempting chained authentication of "+output+ " with manager:"+delegates[i]);
                }
                auth = delegates[i].authenticate(output);
                authenticated = auth.isAuthenticated();
            } catch (AuthenticationException x) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Chained authentication exception:", x);
                }
                lastException = x;
            }
            if (logger.isDebugEnabled()) {
                logger.debug("Chained Authentication status of "+output+ " with manager:"+delegates[i]+"; Authenticated:"+authenticated);
            }
        }
        if (authenticated) {
            return auth;
        } else if (lastException!=null) {
            //we had at least one authentication exception, throw it
            throw lastException;
        } else {
            //not authenticated, but return the last of the result
            return auth;
        }
    }

}
