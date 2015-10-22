/*
 * ******************************************************************************
 *       Cloud Foundry Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *       This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *       You may not use this product except in compliance with the License.
 *
 *       This product includes a number of subcomponents with
 *       separate copyright notices and license terms. Your use of these
 *       subcomponents is subject to the terms and conditions of the
 *       subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class UaaAuthenticationPrototype {
    private List<? extends GrantedAuthority> authorities;
    private Object credentials = null;
    private UaaPrincipal principal;
    private UaaAuthenticationDetails details;
    private boolean authenticated;
    private long authenticatedTime = System.currentTimeMillis();
    private long expiresAt = -1l;
    private Set<String> externalGroups;
    private Map<String, List<String>> attributes;

    private UaaAuthenticationPrototype() {
    }

    public static UaaAuthenticationPrototype alreadyAuthenticated() {
        return new UaaAuthenticationPrototype().withAuthenticated(true).withAuthenticatedTime(System.currentTimeMillis());
    }

    public static UaaAuthenticationPrototype notYetAuthenticated() {
        return new UaaAuthenticationPrototype();
    }

    public UaaAuthenticationPrototype withAuthorities(List<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
        return this;
    }

    public UaaAuthenticationPrototype withCredentials(Object credentials) {
        this.credentials = credentials;
        return this;
    }

    public UaaAuthenticationPrototype withPrincipal(UaaPrincipal principal){
        this.principal = principal;
        return this;
    }

    public UaaAuthenticationPrototype withDetails(UaaAuthenticationDetails details) {
        this.details = details;
        return this;
    }

    public UaaAuthenticationPrototype withAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
        return this;
    }

    public UaaAuthenticationPrototype withAuthenticatedTime(long authenticatedTime) {
        this.authenticatedTime = authenticatedTime;
        return this;
    }

    public UaaAuthenticationPrototype withExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
        return this;
    }

    public UaaAuthenticationPrototype withExternalGroups(Set<String> externalGroups) {
        this.externalGroups = externalGroups;
        return this;
    }

    public UaaAuthenticationPrototype withAttributes(Map<String, List<String>> attributes) {
        this.attributes = attributes;
        return this;
    }


    public List<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Object getCredentials() {
        return credentials;
    }

    public UaaPrincipal getPrincipal() {
        return principal;
    }

    public UaaAuthenticationDetails getDetails() {
        return details;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public long getAuthenticatedTime() {
        return authenticatedTime;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public Set<String> getExternalGroups() {
        return externalGroups;
    }

    public Map<String, List<String>> getAttributes() { return attributes; }
}
