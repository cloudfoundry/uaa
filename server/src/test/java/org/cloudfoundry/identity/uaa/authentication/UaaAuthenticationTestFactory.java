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

import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotNull;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaAuthenticationTestFactory {

    public static UaaPrincipal getPrincipal(String id, String name, String email) {
        return new UaaPrincipal(new MockUaaUserDatabase(u -> u.withId(id).withUsername(name).withEmail(email).withGivenName(name).withFamilyName("familyName")).retrieveUserById(id));
    }

    public static UaaAuthentication getAuthentication(String id, String name, String email) {
        return new UaaAuthentication(getPrincipal(id, name, email), UaaAuthority.USER_AUTHORITIES, null);
    }

    public static UaaAuthentication getAuthentication(String id, String name, String email, @NotNull Set<String> scopes) {
        return new UaaAuthentication(getPrincipal(id, name, email),
                scopes.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()),
                null);
    }

    public static AuthzAuthenticationRequest getAuthenticationRequest(String name) {
        return getAuthenticationRequest(name, false);
    }

    public static AuthzAuthenticationRequest getAuthenticationRequest(String name, boolean addNew) {
        UaaAuthenticationDetails details = null;
        if (addNew) {
            String sessionId = UUID.randomUUID().toString();

            HttpSession session = mock(HttpSession.class);
            when(session.getId()).thenReturn(sessionId);

            HttpServletRequest req = mock(HttpServletRequest.class);
            when(req.getSession()).thenReturn(session);
            when(req.getSession(false)).thenReturn(session);
            when(req.getSession(true)).thenReturn(session);
            when(req.getRemoteAddr()).thenReturn("127.0.0.1");

            when(req.getParameter("client_id")).thenReturn(name);
            when(req.getParameter(UaaAuthenticationDetails.ADD_NEW)).thenReturn(String.valueOf(addNew));
            when(req.getContextPath()).thenReturn("");
            when(req.getRequestURI()).thenReturn("");
            details = new UaaAuthenticationDetails(req);
        }
        return new AuthzAuthenticationRequest(name, "password", details);
    }

}
