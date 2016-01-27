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
package org.cloudfoundry.identity.uaa.security;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.expression.OAuth2ExpressionUtils;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class DefaultSecurityContextAccessor implements SecurityContextAccessor {

    @Override
    public boolean isClient() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();

        if (!(a instanceof OAuth2Authentication)) {
            return false;
        }

        return ((OAuth2Authentication) a).isClientOnly();
    }

    @Override
    public boolean isUser() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();

        if (a instanceof OAuth2Authentication) {
            return !isClient();
        }

        if (a instanceof UaaAuthentication) {
            return true;
        }

        if (a!=null && a.getPrincipal() instanceof UaaPrincipal) {
            return true;
        }

        return false;
    }

    @Override
    public boolean isAdmin() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        String[] adminRoles = new String[] {"uaa.admin"};
        if (a==null) {
            return false;
        }

        boolean result = false;
        if (a instanceof OAuth2Authentication) {
            OAuth2Authentication oa = (OAuth2Authentication)a;
            result = OAuth2ExpressionUtils.hasAnyScope(oa,adminRoles);
        } else {
            result = hasAnyAdminScope(a, adminRoles);
        }

        String zoneAdminRole = "zones."+ IdentityZoneHolder.get().getId()+".admin";
        if (!result) {
            ContextSensitiveOAuth2SecurityExpressionMethods eval = new ContextSensitiveOAuth2SecurityExpressionMethods(a, IdentityZone.getUaa());
            result = eval.hasScopeInAuthZone(zoneAdminRole);
        }
        return result;
    }

    private boolean hasAnyAdminScope(Authentication a, String... adminRoles) {
        Set<String> authorites = (a==null ? Collections.<String>emptySet() : AuthorityUtils.authorityListToSet(a.getAuthorities()));
        for (String s : adminRoles) {
            if (authorites.contains(s)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String getUserId() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a == null ? null : ((UaaPrincipal) a.getPrincipal()).getId();
    }

    @Override
    public String getUserName() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a == null ? null : a.getName();
    }

    @Override
    public String getAuthenticationInfo() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();

        if (a instanceof OAuth2Authentication) {
            OAuth2Authentication oauth = ((OAuth2Authentication) a);

            String info = getClientId();
            if (!oauth.isClientOnly()) {
                info = info + "; " + a.getName() + "; " + getUserId();
            }

            return info;
        } else {
            return a.getName();
        }
    }

    @Override
    public String getClientId() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();

        if (!(a instanceof OAuth2Authentication)) {
            return null;
        }

        return ((OAuth2Authentication) a).getOAuth2Request().getClientId();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a == null ? Collections.<GrantedAuthority> emptySet() : a.getAuthorities();
    }

    @Override
    public Collection<String> getScopes() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (!(a instanceof OAuth2Authentication)) {
            return Collections.emptySet();
        }

        return ((OAuth2Authentication) a).getOAuth2Request().getScope();
    }
}
