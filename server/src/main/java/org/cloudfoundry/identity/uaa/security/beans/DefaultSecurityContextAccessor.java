package org.cloudfoundry.identity.uaa.security.beans;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2ExpressionUtils;
import org.cloudfoundry.identity.uaa.security.ContextSensitiveOAuth2SecurityExpressionMethods;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

@Component
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
        return a != null && a.getPrincipal() instanceof UaaPrincipal;
    }

    @Override
    public boolean isAdmin() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        String[] adminRoles = new String[]{"uaa.admin"};
        if (a == null) {
            return false;
        }

        boolean result = false;
        if (a instanceof OAuth2Authentication oa) {
            result = OAuth2ExpressionUtils.hasAnyScope(oa, adminRoles);
        } else {
            result = hasAnyAdminScope(a, adminRoles);
        }

        String zoneAdminRole = "zones." + IdentityZoneHolder.get().getId() + ".admin";
        if (!result) {
            ContextSensitiveOAuth2SecurityExpressionMethods eval = new ContextSensitiveOAuth2SecurityExpressionMethods(a);
            result = eval.hasScopeInAuthZone(zoneAdminRole);
        }
        return result;
    }

    private boolean hasAnyAdminScope(Authentication a, String... adminRoles) {
        Set<String> authorites = a == null ? Collections.emptySet() : AuthorityUtils.authorityListToSet(a.getAuthorities());
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

        if (a instanceof OAuth2Authentication oauth) {

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
        return a == null ? Collections.<GrantedAuthority>emptySet() : a.getAuthorities();
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
