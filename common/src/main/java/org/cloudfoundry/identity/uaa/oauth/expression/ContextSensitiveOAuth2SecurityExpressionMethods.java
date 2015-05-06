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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.Claims;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.expression.OAuth2SecurityExpressionMethods;
import org.springframework.util.StringUtils;

import java.util.Map;

public class ContextSensitiveOAuth2SecurityExpressionMethods extends OAuth2SecurityExpressionMethods {
    public static final String ZONE_ID = "{zone.id}";

    private final IdentityZone identityZone;
    private final Authentication authentication;

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
        this(authentication, null);
    }

    public ContextSensitiveOAuth2SecurityExpressionMethods(Authentication authentication, IdentityZone authenticationZone) {
        super(authentication);
        this.authentication = authentication;
        this.identityZone = authenticationZone;
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

    public boolean hasScopeInAuthZone(String scope) {
        boolean hasScope = hasScope(scope);
        String authZoneId = getAuthenticationZoneId();
        hasScope = hasScope && StringUtils.hasText(authZoneId);
        if (hasScope) {
            hasScope = identityZone != null && identityZone.getId().equals(authZoneId);
        }
        return hasScope;
    }

    private String getAuthenticationZoneId() {
        if (authentication.getPrincipal() instanceof UaaPrincipal) {
            return ((UaaPrincipal)authentication.getPrincipal()).getZoneId();
        } else if (authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
            String tokenValue = ((OAuth2AuthenticationDetails)authentication.getDetails()).getTokenValue();
            return getZoneIdFromToken(tokenValue);
        } else {
            return null;
        }
    }


    private String getZoneIdFromToken(String token) {
        Jwt tokenJwt = null;
        try {
            tokenJwt = JwtHelper.decode(token);
        } catch (Throwable t) {
            throw new IllegalStateException("Cannot decode token", t);
        }
        Map<String, Object> claims = null;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot read token claims", e);
        }
        return (String)claims.get(Claims.ZONE_ID);
    }
}
