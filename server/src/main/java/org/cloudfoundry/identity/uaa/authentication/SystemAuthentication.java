package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;


public class SystemAuthentication implements Authentication {

    public static final SystemAuthentication SYSTEM_AUTHENTICATION = new SystemAuthentication();

    protected static final String PRINCIPAL = "uaa-system";

    private SystemAuthentication() {
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return PRINCIPAL;
    }

    @Override
    public Object getPrincipal() {
        return PRINCIPAL;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return PRINCIPAL;
    }
}
