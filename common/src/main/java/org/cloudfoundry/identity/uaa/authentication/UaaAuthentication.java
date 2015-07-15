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
package org.cloudfoundry.identity.uaa.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

/**
 * Authentication token which represents a user.
 */
public class UaaAuthentication implements Authentication, Serializable {
    private List<? extends GrantedAuthority> authorities;
    private Object credentials;
    private UaaPrincipal principal;
    private UaaAuthenticationDetails details;
    private boolean authenticated;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the
     *            principal represented by this authentication object.
     */
    public UaaAuthentication(UaaPrincipal principal,
                             List<? extends GrantedAuthority> authorities,
                             UaaAuthenticationDetails details) {
        this(principal, null, authorities, details, true);
    }

    @JsonCreator
    public UaaAuthentication(@JsonProperty("principal") UaaPrincipal principal,
                             @JsonProperty("credentials") Object credentials,
                             @JsonProperty("authorities") List<? extends GrantedAuthority> authorities,
                             @JsonProperty("details") UaaAuthenticationDetails details,
                             @JsonProperty("authenticated") boolean authenticated) {
        if (principal == null || authorities == null) {
            throw new IllegalArgumentException("principal and authorities must not be null");
        }
        this.principal = principal;
        this.authorities = authorities;
        this.details = details;
        this.credentials = credentials;
        this.authenticated = authenticated;
    }

    @Override
    public String getName() {
        // Should we return the ID for the principal name? (No, because the
        // UaaUserDatabase retrieves users by name.)
        return principal.getName();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public UaaPrincipal getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        authenticated = isAuthenticated;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        UaaAuthentication that = (UaaAuthentication) o;

        if (!authorities.equals(that.authorities)) {
            return false;
        }
        if (!principal.equals(that.principal)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = authorities.hashCode();
        result = 31 * result + principal.hashCode();
        return result;
    }
}
