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
package org.cloudfoundry.identity.uaa.authentication.manager;


import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 *
 */
public class ScopeAuthenticationManager implements AuthenticationManager{

    private boolean throwOnNotAuthenticated = true;
    private List<String> requiredScopes;

    public List<String> getRequiredScopes() {
        return requiredScopes;
    }

    public void setRequiredScopes(List<String> requiredScopes) {
        this.requiredScopes = dedup(requiredScopes);
    }

    public boolean isThrowOnNotAuthenticated() {
        return throwOnNotAuthenticated;
    }

    public void setThrowOnNotAuthenticated(boolean throwOnNotAuthenticated) {
        this.throwOnNotAuthenticated = throwOnNotAuthenticated;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof OAuth2Authentication) {
            OAuth2Request creq = ((OAuth2Authentication) authentication).getOAuth2Request();
            List<String> scopes = dedup(creq.getScope());
            int matches = 0;
            int requiredMatches = getRequiredScopes().size();
            for (String scope : scopes) {
                if (requiredScopes.contains(scope)) {
                    matches++;
                }
            }
            if (matches==requiredMatches) {
                authentication.setAuthenticated(true);
                return authentication;
            } else if (isThrowOnNotAuthenticated()) {
                throw new InsufficientScopeException("Insufficient scopes");
            }
        } else if (isThrowOnNotAuthenticated()) {
            throw new InvalidTokenException("Missing Oauth 2 authentication.");
        }
        return authentication;
    }


    public List<String> dedup(Collection<String> list) {
        return new ArrayList<>(new LinkedHashSet<>(list));
    }
}
