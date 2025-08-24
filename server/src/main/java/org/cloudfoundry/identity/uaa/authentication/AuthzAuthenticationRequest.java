/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.user.ExtendedUaaAuthority;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;

/**
 * Authentication request object which contains the JSON data submitted to the
 * /authorize endpoint.
 * 
 * This token is not used to represent an authenticated user.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class AuthzAuthenticationRequest implements Authentication {

    private final UaaAuthenticationDetails details;
    private final Map<String, String> info;

    public AuthzAuthenticationRequest(Map<String, String> info, UaaAuthenticationDetails details) {
        this.info = Collections.unmodifiableMap(info);
        Assert.notNull(details, "[Assertion failed] - details is required; it must not be null");
        this.details = details;
    }

    public AuthzAuthenticationRequest(String username, String password, UaaAuthenticationDetails details) {
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(password, "password cannot be empty");
        this.info = Map.of("username", username.trim(), "password", password.trim());
        this.details = details;
    }

    public Map<String, String> getInfo() {
        return info;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (null != info.get("authorities")) {
            Collection<ExtendedUaaAuthority> returnAuthorities = new LinkedHashSet<>();

            String[] authorities = StringUtils.commaDelimitedListToStringArray(info.get("authorities"));

            for (String authority : authorities) {
                returnAuthorities.add(new ExtendedUaaAuthority(authority, null));
            }

            return returnAuthorities;
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public String getPrincipal() {
        return info.get("username");
    }

    @Override
    public String getCredentials() {
        return info.get("password");
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Authentication request can not be 'authenticated'");
        }
    }

    @Override
    public String getName() {
        return getPrincipal();
    }
}
