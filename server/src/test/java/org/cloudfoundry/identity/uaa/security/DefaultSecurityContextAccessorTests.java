/*******************************************************************************
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
package org.cloudfoundry.identity.uaa.security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Luke Taylor
 */
public class DefaultSecurityContextAccessorTests {

    @After
    public void clearContext() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void clientIsNotUser() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken("client", "secret", UaaAuthority.ADMIN_AUTHORITIES));

        assertFalse(new DefaultSecurityContextAccessor().isUser());
    }

    @Test
    public void uaaUserIsUser() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                        UaaAuthenticationTestFactory.getAuthentication("1234", "user", "user@test.org"));

        assertTrue(new DefaultSecurityContextAccessor().isUser());
    }

    @Test
    public void adminUserIsAdmin() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken("user", "password", UaaAuthority.ADMIN_AUTHORITIES));

        assertTrue(new DefaultSecurityContextAccessor().isAdmin());
    }

    @Test
    public void adminClientIsAdmin() throws Exception {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", null);
        authorizationRequest.setScope(UaaAuthority.ADMIN_AUTHORITIES.stream().map(UaaAuthority::getAuthority).collect(Collectors.toList()));
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null));

        assertTrue(new DefaultSecurityContextAccessor().isAdmin());
    }

    @Test
    public void zoneAdminUserIsAdmin() throws Exception {

        BaseClientDetails client = new BaseClientDetails();
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        authorities.add(new SimpleGrantedAuthority("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        client.setAuthorities(authorities);

        UaaPrincipal principal = new UaaPrincipal("id","username","email", OriginKeys.UAA,null,IdentityZoneHolder.get().getId());
        UaaAuthentication userAuthentication = new UaaAuthentication(principal, authorities, new UaaAuthenticationDetails(new MockHttpServletRequest()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", UaaStringUtils.getStringsFromAuthorities(authorities));
        authorizationRequest.setResourceIdsAndAuthoritiesFromClientDetails(client);
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication));

        assertTrue(new DefaultSecurityContextAccessor().isAdmin());

    }

    @Test
    public void zoneAdminUserIsNotAdmin_BecauseOriginIsNotUaa() throws Exception {

        BaseClientDetails client = new BaseClientDetails();
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        authorities.add(new SimpleGrantedAuthority("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        client.setAuthorities(authorities);

        UaaPrincipal principal = new UaaPrincipal("id","username","email", OriginKeys.UAA,null, MultitenancyFixture.identityZone("test","test").getId());
        UaaAuthentication userAuthentication = new UaaAuthentication(principal, authorities, new UaaAuthenticationDetails(new MockHttpServletRequest()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", UaaStringUtils.getStringsFromAuthorities(authorities));
        authorizationRequest.setResourceIdsAndAuthoritiesFromClientDetails(client);
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication));

        assertFalse(new DefaultSecurityContextAccessor().isAdmin());

    }

    @Test
    public void zoneAdminClientIsAdmin() throws Exception {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", null);
        authorizationRequest.setScope(Arrays.asList("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiI2ZjIxOTFlYi1iODY2LTQxZDUtYTBjNy1kZTg0ZTE3OTQ3MjIiLCJzdWIiOiJhZG1pbiIsImF1dGhvcml0aWVzIjpbInNjaW0ucmVhZCIsInVhYS5hZG1pbiIsInpvbmVzLmU5ZmY4ZDJmLTk5ODEtNDhkNi04MmIzLWNjYTc0ZGY5YzFmZS5hZG1pbiIsInBhc3N3b3JkLndyaXRlIiwic2NpbS53cml0ZSIsImNsaWVudHMud3JpdGUiLCJjbGllbnRzLnJlYWQiLCJ6b25lcy5yZWFkIiwiY2xpZW50cy5zZWNyZXQiXSwic2NvcGUiOlsic2NpbS5yZWFkIiwidWFhLmFkbWluIiwiem9uZXMuZTlmZjhkMmYtOTk4MS00OGQ2LTgyYjMtY2NhNzRkZjljMWZlLmFkbWluIiwicGFzc3dvcmQud3JpdGUiLCJzY2ltLndyaXRlIiwiY2xpZW50cy53cml0ZSIsImNsaWVudHMucmVhZCIsInpvbmVzLnJlYWQiLCJjbGllbnRzLnNlY3JldCJdLCJjbGllbnRfaWQiOiJhZG1pbiIsImNpZCI6ImFkbWluIiwiYXpwIjoiYWRtaW4iLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6ImVjMWMzN2M0IiwiaWF0IjoxNDM2NTcwMjkzLCJleHAiOjE0MzY2MTM0OTMsImlzcyI6Imh0dHBzOi8vdWFhLmlkZW50aXR5LmNmLWFwcC5jb20vb2F1dGgvdG9rZW4iLCJ6aWQiOiJ1YWEiLCJhdWQiOlsiYWRtaW4iLCJzY2ltIiwidWFhIiwiem9uZXMuZTlmZjhkMmYtOTk4MS00OGQ2LTgyYjMtY2NhNzRkZjljMWZlIiwicGFzc3dvcmQiLCJjbGllbnRzIiwiem9uZXMiXX0.ajpOTnvAvHWPEXEZI4XXDIO_Omp03VgQ64W2bfbrGSIVB0lBujegXvXe-61bRqiKKbbkk85Z6AXUfz6aZXb2hjKPeZr8P9ydy23bSCsl9QNsM9D_h3KHzTkJ9G-34aMTpVi8hxmfr_UQ6J-37zoTTIQrk5nxIiwxc4HcKkl_p68");
        authentication.setDetails(new OAuth2AuthenticationDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        assertTrue(new DefaultSecurityContextAccessor().isAdmin());
    }


}
