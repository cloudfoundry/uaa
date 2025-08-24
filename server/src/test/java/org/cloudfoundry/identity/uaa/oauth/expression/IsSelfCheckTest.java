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
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.emptySet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class IsSelfCheckTest {

    private IsSelfCheck bean;
    private UaaAuthentication authentication;
    private String id;
    private String clientId;
    private MockHttpServletRequest request;
    private UaaPrincipal principal;
    private RevocableTokenProvisioning tokenProvisioning;
    private OAuth2Authentication oAuth2AuthenticationWithUser;
    private OAuth2Authentication oAuth2AuthenticationWithoutUser;

    @BeforeEach
    void getBean() {
        id = new AlphanumericRandomValueStringGenerator(25).generate();
        clientId = id;
        request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        principal = new UaaPrincipal(id, "username", "username@email.org", OriginKeys.UAA, null, IdentityZoneHolder.get().getId());
        authentication = new UaaAuthentication(principal, Collections.<GrantedAuthority>emptyList(), new UaaAuthenticationDetails(request));
        OAuth2Request request = new OAuth2Request(emptyMap(), clientId, emptyList(), true, emptySet(), emptySet(), null, emptySet(), emptyMap());
        oAuth2AuthenticationWithUser = new OAuth2Authentication(request, authentication);
        oAuth2AuthenticationWithoutUser = new OAuth2Authentication(request, null);
        tokenProvisioning = Mockito.mock(RevocableTokenProvisioning.class);
        bean = new IsSelfCheck(tokenProvisioning);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void selfCheckLastUaaAuth() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setPathInfo("/Users/" + id);
        assertThat(bean.isUserSelf(request, 1)).isTrue();
    }

    @Test
    void selfCheckSecondUaaAuth() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setPathInfo("/Users/" + id + "/verify");
        assertThat(bean.isUserSelf(request, 1)).isTrue();
    }

    @Test
    void selfCheckTokenAuth() {
        UaaClientDetails client = new UaaClientDetails();
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        authorities.add(new SimpleGrantedAuthority("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        client.setAuthorities(authorities);
        UaaAuthentication userAuthentication = new UaaAuthentication(principal, authorities, new UaaAuthenticationDetails(request));
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", UaaStringUtils.getStringsFromAuthorities(authorities));
        authorizationRequest.setResourceIdsAndAuthoritiesFromClientDetails(client);
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication));

        request.setPathInfo("/Users/" + id + "/verify");
        assertThat(bean.isUserSelf(request, 1)).isTrue();

        request.setPathInfo("/Users/" + id);
        assertThat(bean.isUserSelf(request, 1)).isTrue();
    }

    @Test
    void selfCheckTokenClientAuthFails() {
        UaaClientDetails client = new UaaClientDetails();
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        authorities.add(new SimpleGrantedAuthority("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        client.setAuthorities(authorities);
        UaaAuthentication userAuthentication = null;
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", UaaStringUtils.getStringsFromAuthorities(authorities));
        authorizationRequest.setResourceIdsAndAuthoritiesFromClientDetails(client);
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication));

        request.setPathInfo("/Users/" + id + "/verify");
        assertThat(bean.isUserSelf(request, 1)).isFalse();

        request.setPathInfo("/Users/" + id);
        assertThat(bean.isUserSelf(request, 1)).isFalse();
    }

    @Test
    void selfUserToken() {
        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithUser);
        request.setPathInfo("/oauth/token/revoke/user/" + id);
        assertThat(bean.isUserTokenRevocationForSelf(request, 4)).isTrue();

        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithoutUser);
        assertThat(bean.isUserTokenRevocationForSelf(request, 4)).isFalse();

        request.setPathInfo("/oauth/token/revoke/user/" + "other-user-id");
        assertThat(bean.isUserTokenRevocationForSelf(request, 4)).isFalse();
    }

    @Test
    void selfClientToken() {
        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithUser);
        request.setPathInfo("/oauth/token/revoke/client/" + clientId);
        assertThat(bean.isClientTokenRevocationForSelf(request, 4)).isTrue();

        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithoutUser);
        assertThat(bean.isClientTokenRevocationForSelf(request, 4)).isTrue();

        request.setPathInfo("/oauth/token/revoke/client/" + "other-client-id");
        assertThat(bean.isClientTokenRevocationForSelf(request, 4)).isFalse();
    }

    @Test
    void ensure_revoke_self_detects_client_vs_user() {
        RevocableToken revocableUserToken = new RevocableToken()
                .setTokenId("token-id")
                .setUserId(id)
                .setClientId(clientId);
        request.setPathInfo("/oauth/token/revoke/" + revocableUserToken.getTokenId());
        when(tokenProvisioning.retrieve(eq(revocableUserToken.getTokenId()), eq(IdentityZoneHolder.get().getId()))).thenReturn(revocableUserToken);

        //test with user authentication
        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithUser);
        assertThat(bean.isTokenRevocationForSelf(request, 3)).isTrue();
        //change the user id on the token
        revocableUserToken.setUserId("other-user-id");
        //still succeed, the client matches
        assertThat(bean.isTokenRevocationForSelf(request, 3)).isTrue();
        //change the client id on the token
        revocableUserToken.setClientId("other-client-id");
        //should fail
        assertThat(bean.isTokenRevocationForSelf(request, 3)).isFalse();
        //restore user id
        revocableUserToken.setUserId(id);
        //succeed, the user matches
        assertThat(bean.isTokenRevocationForSelf(request, 3)).isTrue();

        //test with client authentication
        SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationWithoutUser);
        revocableUserToken.setClientId(clientId);
        assertThat(bean.isTokenRevocationForSelf(request, 3)).isTrue();
        //change the client id on the token
        revocableUserToken.setClientId("other-client-id");
        //should fail
        assertThat(bean.isTokenRevocationForSelf(request, 3)).isFalse();
    }
}
