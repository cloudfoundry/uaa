/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.logging.SanitizedLogFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Chained authentication manager that works of simple conditions
 */
public class ChainedAuthenticationManager implements AuthenticationManager {
    public static final String IF_PREVIOUS_FALSE = "ifPreviousFalse";
    public static final String IF_PREVIOUS_TRUE = "ifPreviousTrue";

    protected final SanitizedLogFactory.SanitizedLog logger = SanitizedLogFactory.getLog(getClass());

    private AuthenticationManagerConfiguration[] delegates;

    public ChainedAuthenticationManager() {
    }

    public AuthenticationManagerConfiguration[] getDelegates() {
        return delegates;
    }

    public void setDelegates(AuthenticationManagerConfiguration[] delegates) {
        this.delegates = delegates;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof Authentication)) {
            return null;
        }
        UsernamePasswordAuthenticationToken output = null;
        if (authentication instanceof UsernamePasswordAuthenticationToken token) {
            output = token;
        } else {
            output = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
                    (authentication.getCredentials() != null ? authentication.getCredentials().toString() : null),
                    authentication.getAuthorities());
            output.setDetails(authentication.getDetails());
        }
        boolean authenticated = false;
        Authentication auth = null;
        AuthenticationException lastException = null;
        boolean lastResult = false;
        boolean shallContinue = true;
        if (delegates == null || delegates.length == 0) {
            throw new ProviderNotFoundException("No available authentication providers.");
        }
        for (int i = 0; shallContinue && i < delegates.length; i++) {

            boolean shallAuthenticate = (i == 0) ||
                    (lastResult && IF_PREVIOUS_TRUE.equals(delegates[i].getRequired())) ||
                    ((!lastResult) && IF_PREVIOUS_FALSE.equals(delegates[i].getRequired()));

            if (shallAuthenticate) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Attempting chained authentication of " + output + " with manager:" + delegates[i].getAuthenticationManager() + " required:" + delegates[i].getRequired());
                }
                Authentication thisAuth = null;
                try {
                    thisAuth = delegates[i].getAuthenticationManager().authenticate(auth != null ? auth : output);
                } catch (AuthenticationException x) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Chained authentication exception:" + x.getMessage() + " at:" + (x.getStackTrace().length > 0 ? x.getStackTrace()[0] : "(no stack trace)"));
                    }
                    lastException = x;
                    if (delegates[i].getStopIf() != null) {
                        for (Class<? extends AuthenticationException> exceptionClass : delegates[i].getStopIf()) {
                            if (exceptionClass.isAssignableFrom(x.getClass())) {
                                shallContinue = false;
                                break;
                            }
                        }
                    }
                }
                lastResult = thisAuth != null && thisAuth.isAuthenticated();

                if (lastResult) {
                    authenticated = true;
                    auth = thisAuth;
                } else {
                    authenticated = false;
                    auth = null;
                }

            } else {
                shallContinue = false;
            }
            if (logger.isDebugEnabled()) {
                logger.debug("Chained Authentication status of " + output + " with manager:" + delegates[i] + "; Authenticated:" + authenticated);
            }
        }
        if (authenticated) {
            return auth;
        } else if (lastException != null) {
            //we had at least one authentication exception, throw it
            throw lastException;
        } else {
            //not authenticated, but return the last of the result
            return auth;
        }
    }

    public static class AuthenticationManagerConfiguration {
        private AuthenticationManager authenticationManager;
        private String required;
        private Class<? extends AuthenticationException>[] stopIf;

        public Class<? extends AuthenticationException>[] getStopIf() {
            return stopIf;
        }

        public void setStopIf(Class<? extends AuthenticationException>... stopIf) {
            this.stopIf = stopIf;
        }

        public AuthenticationManagerConfiguration() {
        }

        public AuthenticationManagerConfiguration(AuthenticationManager authenticationManager, String required) {
            this.authenticationManager = authenticationManager;
            this.required = required;
        }

        public AuthenticationManager getAuthenticationManager() {
            return authenticationManager;
        }

        public void setAuthenticationManager(AuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
        }

        public String getRequired() {
            return required;
        }

        public void setRequired(String required) {
            boolean valid = false;
            if (IF_PREVIOUS_FALSE.equals(required) ||
                    IF_PREVIOUS_TRUE.equals(required)) {
                valid = true;
            }

            if (!valid) {
                throw new IllegalArgumentException(required + " is not a valid value for property 'required'");
            }

            this.required = required;
        }
    }

}
