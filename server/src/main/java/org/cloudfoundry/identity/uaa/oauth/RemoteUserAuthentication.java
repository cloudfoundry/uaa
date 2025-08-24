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

package org.cloudfoundry.identity.uaa.oauth;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Authentication token representing a user decoded from a UAA access token.
 * 
 * @author Dave Syer
 * 
 */
public class RemoteUserAuthentication extends AbstractAuthenticationToken implements Authentication {

    private final String id;
    private final String username;
    private final String email;

    public RemoteUserAuthentication(String id, String username, String email,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.id = id;
        this.username = username;
        this.email = email;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "<N/A>";
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    public String getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

}
