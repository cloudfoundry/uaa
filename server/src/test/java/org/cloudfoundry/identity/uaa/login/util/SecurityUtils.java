/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.login.util;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.Collections;
import java.util.LinkedList;
import java.util.Set;

import static org.junit.Assert.assertTrue;

public final class SecurityUtils {

    private SecurityUtils() {}

    public static SecurityContext defaultSecurityContext(Authentication authentication) {
        SecurityContext securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(authentication);
        return securityContext;
    }

    public static Authentication fullyAuthenticatedUser(String id, String username, String email, GrantedAuthority... authorities) {
        UaaPrincipal p = new UaaPrincipal(id, username, email, OriginKeys.UAA,"", IdentityZoneHolder.get().getId());
        LinkedList<GrantedAuthority> grantedAuthorities = new LinkedList<>();
        Collections.addAll(grantedAuthorities, authorities);
        UaaAuthentication auth = new UaaAuthentication(p, "", grantedAuthorities, new UaaAuthenticationDetails(new MockHttpServletRequest()),true, System.currentTimeMillis());
        assertTrue(auth.isAuthenticated());
        return auth;
    }

   public static Authentication oauthAuthenticatedClient(String clientId, Set<String> scopes, Set<GrantedAuthority> authorities) {
        OAuth2Authentication auth = new OAuth2Authentication(new OAuth2Request(null, clientId, authorities, true, scopes, null, null, null, null), null);
        assertTrue(auth.isAuthenticated());
        return auth;
   }

    public static Authentication oauthAuthenticatedUser(
        String clientId, Set<String> scopes, Set<GrantedAuthority> authorities,
        String id, String username, String email, GrantedAuthority... userAuthorities) {
        OAuth2Authentication auth = new OAuth2Authentication(new OAuth2Request(null, clientId, authorities, true, scopes, null, null, null, null), fullyAuthenticatedUser(id, username, email, userAuthorities));
        assertTrue(auth.isAuthenticated());
        return auth;
    }
}
