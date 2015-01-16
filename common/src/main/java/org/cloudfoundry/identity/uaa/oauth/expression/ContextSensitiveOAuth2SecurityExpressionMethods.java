/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.expression;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2SecurityExpressionMethods;

public class ContextSensitiveOAuth2SecurityExpressionMethods extends OAuth2SecurityExpressionMethods {
    public static final String ZONE_ID = "{zone.id}";

    private String replaceContext(String role) {
        IdentityZone zone = IdentityZoneHolder.get();
        return role.replace(ZONE_ID, zone.getId());
    }

    private String[] replaceContext(String[] roles) {
        if (roles==null || roles.length==0) {
            return roles;
        }
        String[] adjusted = new String[roles.length];
        for (int i=0; i<roles.length; i++) {
            adjusted[i] = replaceContext(roles[i]);
        }
        return adjusted;
    }

    public ContextSensitiveOAuth2SecurityExpressionMethods(Authentication authentication) {
        super(authentication);
    }

    @Override
    public boolean clientHasRole(String role) {
        return super.clientHasRole(replaceContext(role));
    }

    @Override
    public boolean clientHasAnyRole(String... roles) {
        return super.clientHasAnyRole(replaceContext(roles));
    }

    @Override
    public boolean hasScope(String scope) {
        return super.hasScope(replaceContext(scope));
    }

    @Override
    public boolean hasAnyScope(String... scopes) {
        return super.hasAnyScope(replaceContext(scopes));
    }

    @Override
    public boolean hasScopeMatching(String scopeRegex) {
        return super.hasScopeMatching(replaceContext(scopeRegex));
    }

    @Override
    public boolean hasAnyScopeMatching(String... scopesRegex) {
        return super.hasAnyScopeMatching(replaceContext(scopesRegex));
    }
}
