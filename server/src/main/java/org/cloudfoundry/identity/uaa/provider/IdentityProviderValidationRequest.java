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
package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.authentication.NonStringPassword;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class IdentityProviderValidationRequest {

    private final IdentityProvider provider;
    private final UsernamePasswordAuthentication credentials;

    @JsonCreator
    public IdentityProviderValidationRequest(
            @JsonProperty("provider") IdentityProvider provider,
            @JsonProperty("credentials") UsernamePasswordAuthentication credentials
    ) {
        this.provider = provider;
        this.credentials = credentials;
    }

    public UsernamePasswordAuthentication getCredentials() {
        return credentials;
    }

    public IdentityProvider getProvider() {
        return provider;
    }

    public static class UsernamePasswordAuthentication implements Authentication {
        private final String username;
        private final transient NonStringPassword password;

        @JsonCreator
        public UsernamePasswordAuthentication(
                @JsonProperty("username") String username,
                @JsonProperty("password") String password) {
            this.password = new NonStringPassword(password);
            this.username = username;
        }

        public String getPassword() {
            return password.getPassword();
        }

        public String getUsername() {
            return username;
        }

        @JsonIgnore
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return null;
        }

        @JsonIgnore
        @Override
        public Object getCredentials() {
            return getPassword();
        }

        @JsonIgnore
        @Override
        public Object getDetails() {
            return null;
        }

        @JsonIgnore
        @Override
        public Object getPrincipal() {
            return getUsername();
        }

        @JsonIgnore
        @Override
        public boolean isAuthenticated() {
            return false;
        }

        @JsonIgnore
        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        }

        @JsonIgnore
        @Override
        public String getName() {
            return getUsername();
        }
    }
}
