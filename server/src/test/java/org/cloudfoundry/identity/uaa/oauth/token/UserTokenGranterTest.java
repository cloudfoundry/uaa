/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.*;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.USER_TOKEN_REQUESTING_CLIENT_ID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;


public class UserTokenGranterTest {

    private UserTokenGranter granter;
    private AuthorizationServerTokenServices tokenServices;
    private MultitenantClientServices clientDetailsService;
    private OAuth2RequestFactory requestFactory;
    private UaaOauth2Authentication authentication;
    private TokenRequest tokenRequest;
    private UaaAuthentication userAuthentication;
    private Map<String,String> requestParameters;
    private BaseClientDetails requestingClient;
    private BaseClientDetails receivingClient;
    private RevocableTokenProvisioning tokenStore;

    @Before
    public void setup() {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(MultitenantClientServices.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        authentication = mock(UaaOauth2Authentication.class);
        tokenStore = mock(RevocableTokenProvisioning.class);

        userAuthentication = mock(UaaAuthentication.class);
        granter = new UserTokenGranter(
            tokenServices,
            clientDetailsService,
            requestFactory,
            tokenStore
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        requestingClient = new BaseClientDetails("requestingId",null,"uaa.user",GRANT_TYPE_USER_TOKEN, null);
        receivingClient =  new BaseClientDetails("receivingId",null,"test.scope",GRANT_TYPE_REFRESH_TOKEN, null);
        when(clientDetailsService.loadClientByClientId(eq(requestingClient.getClientId()), anyString())).thenReturn(requestingClient);
        when(clientDetailsService.loadClientByClientId(eq(receivingClient.getClientId()), anyString())).thenReturn(receivingClient);
        requestParameters = new HashMap<>();
        requestParameters.put(USER_TOKEN_REQUESTING_CLIENT_ID, requestingClient.getClientId());
        requestParameters.put(GRANT_TYPE, TokenConstants.GRANT_TYPE_USER_TOKEN);
        requestParameters.put(CLIENT_ID, receivingClient.getClientId());
        tokenRequest = new PublicTokenRequest();
        tokenRequest.setRequestParameters(requestParameters);


    }

    @After
    public void teardown() {
        SecurityContextHolder.clearContext();
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void test_no_authentication() {
        SecurityContextHolder.clearContext();
        granter.validateRequest(tokenRequest);
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void test_not_authenticated() {
        when(authentication.isAuthenticated()).thenReturn(false);
        granter.validateRequest(tokenRequest);
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void test_not_a_user_authentication() {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getUserAuthentication()).thenReturn(null);
        granter.validateRequest(tokenRequest);
    }

    @Test(expected = InvalidGrantException.class)
    public void test_invalid_grant_type() {
        missing_parameter(GRANT_TYPE);
    }

    @Test(expected = InvalidGrantException.class)
    public void test_requesting_client_id_missing() {
        missing_parameter(USER_TOKEN_REQUESTING_CLIENT_ID);
    }

    @Test(expected = InvalidClientException.class)
    public void test_wrong_requesting_grant_type() {
        requestingClient.setAuthorizedGrantTypes(Collections.singletonList("password"));
        missing_parameter("non existent");
    }

    @Test(expected = InvalidClientException.class)
    public void test_wrong_receiving_grant_type() {
        receivingClient.setAuthorizedGrantTypes(Collections.singletonList("password"));
        missing_parameter("non existent");
    }

    @Test
    public void ensure_that_access_token_is_deleted_and_modified() {
        String tokenId = "access_token";
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(tokenId);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken("refresh_token");
        Map<String,Object> info = new HashMap(token.getAdditionalInformation());
        info.put(JTI, token.getValue());
        token.setAdditionalInformation(info);
        token.setRefreshToken(refreshToken);
        token.setExpiration(new Date());

        DefaultOAuth2AccessToken result = granter.prepareForSerialization(token);
        assertSame(token, result);
        assertEquals(refreshToken.getValue(), result.getAdditionalInformation().get(JTI));
        assertNull(result.getValue());
        verify(tokenStore).delete(eq(tokenId), anyInt(), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    public void ensure_client_gets_swapped() {
        granter = new UserTokenGranter(
            tokenServices,
            clientDetailsService,
            requestFactory,
            tokenStore
        ) {
            @Override
            protected DefaultOAuth2AccessToken prepareForSerialization(DefaultOAuth2AccessToken token) {
                return null; //override for testing
            }

            @Override
            protected Authentication validateRequest(TokenRequest request) {
                return userAuthentication;
            }
        };

        granter.getAccessToken(requestingClient, tokenRequest);
        verify(clientDetailsService, times(1)).loadClientByClientId(eq(receivingClient.getClientId()), anyString());

    }

    @Test
    public void happy_day() {
        missing_parameter("non existent");
    }

    protected void missing_parameter(String parameter) {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getUserAuthentication()).thenReturn(null);
        when(authentication.getUserAuthentication()).thenReturn(userAuthentication);
        when(userAuthentication.isAuthenticated()).thenReturn(true);
        requestParameters.remove(parameter);
        tokenRequest = new PublicTokenRequest();
        tokenRequest.setClientId(receivingClient.getClientId());
        tokenRequest.setRequestParameters(requestParameters);
        tokenRequest.setGrantType(requestParameters.get(GRANT_TYPE));
        granter.validateRequest(tokenRequest);
    }

    public static class PublicTokenRequest extends TokenRequest {
        public PublicTokenRequest() {
        }
    }
}