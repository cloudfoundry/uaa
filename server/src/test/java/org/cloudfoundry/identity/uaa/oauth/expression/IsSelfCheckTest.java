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
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class IsSelfCheckTest {

    private IsSelfCheck bean;
    private UaaAuthentication authentication;
    private String id;
    private String clientId;
    private MockHttpServletRequest request;
    private UaaPrincipal principal;
    private RevocableTokenProvisioning tokenProvisioning;
    private OAuth2Authentication oAuth2AuthenticationWithUser;
    private OAuth2Authentication oAuth2AuthenticationWithoutUser;

    @Before
    public void getBean() {
        id = new RandomValueStringGenerator(25).generate();
        clientId = id;
        request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        principal = new UaaPrincipal(id, "username","username@email.org", OriginKeys.UAA, null, IdentityZoneHolder.get().getId());
        authentication = new UaaAuthentication(principal, Collections.<GrantedAuthority>emptyList(), new UaaAuthenticationDetails(request));
        OAuth2Request request = new OAuth2Request(emptyMap(), clientId, emptyList(), true, emptySet(), emptySet(), null, emptySet(), emptyMap());
        oAuth2AuthenticationWithUser = new OAuth2Authentication(request, authentication);
        oAuth2AuthenticationWithoutUser = new OAuth2Authentication(request, null);
        tokenProvisioning = Mockito.mock(RevocableTokenProvisioning.class);
        bean = new IsSelfCheck(tokenProvisioning);
    }



    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testSelfCheckLastUaaAuth() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setPathInfo("/Users/"+id);
        assertTrue(bean.isUserSelf(request, 1));
    }

    @Test
    public void testSelfCheckSecondUaaAuth() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setPathInfo("/Users/" + id + "/verify");
        assertTrue(bean.isUserSelf(request,1));
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
        assertTrue(bean.isUserSelf(request, 1));

        request.setPathInfo("/Users/"+id);
        assertTrue(bean.isUserSelf(request, 1));
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
        assertFalse(bean.isUserSelf(request, 1));

        request.setPathInfo("/Users/"+id);
        assertFalse(bean.isUserSelf(request, 1));
    }

    @Test
    public void testSelfUserToken() {
        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithUser);
        request.setPathInfo("/oauth/token/revoke/user/" + id);
        assertTrue(bean.isUserTokenRevocationForSelf(request, 4));

        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithoutUser);
        assertFalse(bean.isUserTokenRevocationForSelf(request, 4));

        request.setPathInfo("/oauth/token/revoke/user/" + "other-user-id");
        assertFalse(bean.isUserTokenRevocationForSelf(request, 4));
    }



    @Test
    public void testSelfClientToken() {
        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithUser);
        request.setPathInfo("/oauth/token/revoke/client/" + clientId);
        assertTrue(bean.isClientTokenRevocationForSelf(request, 4));

        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithoutUser);
        assertTrue(bean.isClientTokenRevocationForSelf(request, 4));

        request.setPathInfo("/oauth/token/revoke/client/" + "other-client-id");
        assertFalse(bean.isClientTokenRevocationForSelf(request, 4));
    }

    @Test
    public void ensure_revoke_self_detects_client_vs_user() {
        RevocableToken revocableUserToken = new RevocableToken()
            .setTokenId("token-id")
            .setUserId(id)
            .setClientId(clientId);
        request.setPathInfo("/oauth/token/revoke/"+revocableUserToken.getTokenId());
        when(tokenProvisioning.retrieve(eq(revocableUserToken.getTokenId()), eq(IdentityZoneHolder.get().getId()))).thenReturn(revocableUserToken);

        //test with user authentication
        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithUser);
        assertTrue(bean.isTokenRevocationForSelf(request, 3));
        //change the user id on the token
        revocableUserToken.setUserId("other-user-id");
        //still succeed, the client matches
        assertTrue(bean.isTokenRevocationForSelf(request, 3));
        //change the client id on the token
        revocableUserToken.setClientId("other-client-id");
        //should fail
        assertFalse(bean.isTokenRevocationForSelf(request, 3));
        //restore user id
        revocableUserToken.setUserId(id);
        //succeed, the user matches
        assertTrue(bean.isTokenRevocationForSelf(request, 3));

        //test with client authentication
        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithoutUser);
        revocableUserToken.setClientId(clientId);
        assertTrue(bean.isTokenRevocationForSelf(request, 3));
        //change the client id on the token
        revocableUserToken.setClientId("other-client-id");
        //should fail
        assertFalse(bean.isTokenRevocationForSelf(request, 3));
    }
}
