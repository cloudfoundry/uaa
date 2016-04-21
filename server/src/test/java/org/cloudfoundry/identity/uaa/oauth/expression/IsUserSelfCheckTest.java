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

package org.cloudfoundry.identity.uaa.oauth.expression;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.security.IsUserSelfCheck;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.*;

public class IsUserSelfCheckTest {

    private IsUserSelfCheck bean;
    private UaaAuthentication authentication;
    private String id;
    private MockHttpServletRequest request;
    private UaaPrincipal principal;

    @Before
    public void getBean() {
        id = new RandomValueStringGenerator(25).generate();
        request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        principal = new UaaPrincipal(id, "username","username@email.org", OriginKeys.UAA, null, IdentityZoneHolder.get().getId());
        authentication = new UaaAuthentication(principal, Collections.<GrantedAuthority>emptyList(), new UaaAuthenticationDetails(request));
        bean = new IsUserSelfCheck();
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testSelfCheckLastUaaAuth() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setPathInfo("/Users/"+id);
        assertTrue(bean.isSelf(request, 1));
    }

    @Test
    public void testSelfCheckSecondUaaAuth() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setPathInfo("/Users/" + id + "/verify");
        assertTrue(bean.isSelf(request,1));
    }

    @Test
    public void testSelfCheck_TokenAuth() {
        BaseClientDetails client = new BaseClientDetails();
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        authorities.add(new SimpleGrantedAuthority("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        client.setAuthorities(authorities);
        UaaAuthentication userAuthentication = new UaaAuthentication(principal, authorities, new UaaAuthenticationDetails(request));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", UaaStringUtils.getStringsFromAuthorities(authorities));
        authorizationRequest.setResourceIdsAndAuthoritiesFromClientDetails(client);
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication));

        request.setPathInfo("/Users/" + id + "/verify");
        assertTrue(bean.isSelf(request, 1));

        request.setPathInfo("/Users/"+id);
        assertTrue(bean.isSelf(request, 1));
    }

    @Test
    public void testSelfCheck_Token_ClientAuth_Fails() {
        BaseClientDetails client = new BaseClientDetails();
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        authorities.add(new SimpleGrantedAuthority("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        client.setAuthorities(authorities);
        UaaAuthentication userAuthentication = null;
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", UaaStringUtils.getStringsFromAuthorities(authorities));
        authorizationRequest.setResourceIdsAndAuthoritiesFromClientDetails(client);
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication));

        request.setPathInfo("/Users/" + id + "/verify");
        assertFalse(bean.isSelf(request, 1));

        request.setPathInfo("/Users/"+id);
        assertFalse(bean.isSelf(request, 1));
    }

}
