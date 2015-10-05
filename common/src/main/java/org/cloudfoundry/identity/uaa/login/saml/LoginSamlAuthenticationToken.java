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
package org.cloudfoundry.identity.uaa.login.saml;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;

import java.util.List;


public class LoginSamlAuthenticationToken extends ExpiringUsernameAuthenticationToken {

    private final UaaPrincipal uaaPrincipal;

    public LoginSamlAuthenticationToken(UaaPrincipal uaaPrincipal, ExpiringUsernameAuthenticationToken token) {
        super(token.getTokenExpiration(), uaaPrincipal, token.getCredentials(), token.getAuthorities());
        this.uaaPrincipal = uaaPrincipal;

    }

    public UaaPrincipal getUaaPrincipal() {
        return uaaPrincipal;
    }

    public UaaAuthentication getUaaAuthentication(List<? extends GrantedAuthority> uaaAuthorityList) {
        return new UaaAuthentication(getUaaPrincipal(), getCredentials(), uaaAuthorityList, null, isAuthenticated(), System.currentTimeMillis(), getTokenExpiration()==null ? -1l : getTokenExpiration().getTime());
    }
}
