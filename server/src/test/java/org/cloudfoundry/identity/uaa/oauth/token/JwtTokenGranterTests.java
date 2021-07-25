/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;

public class JwtTokenGranterTests {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private JwtTokenGranter granter;
    private TokenRequest tokenRequest;
    private ClientDetails client;
    private UaaOauth2Authentication authentication;
    private UaaAuthentication uaaAuthentication;
    private AuthorizationServerTokenServices tokenServices;
    private MultitenantClientServices clientDetailsService;
    private OAuth2RequestFactory requestFactory;
    private Map<String, String> requestParameters;

    @Before
    public void setUp() {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(MultitenantClientServices.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        granter = spy(new JwtTokenGranter(tokenServices, clientDetailsService, requestFactory));
        tokenRequest = new TokenRequest(Collections.emptyMap(), "client_ID", Collections.emptySet(), GRANT_TYPE_JWT_BEARER);

        authentication = mock(UaaOauth2Authentication.class);
        UaaUser user = new UaaUser("id",
                                   "username",
                                   null,
                                   "user@user.org",
                                   Collections.emptyList(),
                                   "Firstname",
                                   "lastName",
                                   new Date(),
                                   new Date(),
                                   OriginKeys.OIDC10,
                                   null,
                                   true,
                                   IdentityZoneHolder.get().getId(),
                                   "salt",
                                   new Date()
        );
        uaaAuthentication = new UaaAuthentication(
            new UaaPrincipal(user), Collections.emptyList(), null
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        client = new BaseClientDetails("clientID",null,"uaa.user",GRANT_TYPE_JWT_BEARER, null);
        when(clientDetailsService.loadClientByClientId(eq(client.getClientId()), anyString())).thenReturn(client);
        requestParameters = new HashMap<>();
        requestParameters.put(OAuth2Utils.CLIENT_ID, client.getClientId());
        requestParameters.put(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        tokenRequest.setRequestParameters(requestParameters);
    }

    @After
    public void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    public void non_authentication_validates_correctly() {
        exception.expect(InvalidGrantException.class);
        exception.expectMessage("User authentication not found");
        granter.validateRequest(tokenRequest);
    }

    @Test
    public void client_authentication_only() {
        exception.expect(InvalidGrantException.class);
        exception.expectMessage("User authentication not found");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        granter.validateRequest(tokenRequest);
    }

    @Test
    public void missing_token_request() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        exception.expect(InvalidGrantException.class);
        exception.expectMessage("Missing token request object");
        granter.validateRequest(null);
    }

    @Test
    public void missing_request_parameters() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        exception.expect(InvalidGrantException.class);
        exception.expectMessage("Missing token request object");
        tokenRequest.setRequestParameters(Collections.emptyMap());
        granter.validateRequest(tokenRequest);
    }

    @Test
    public void missing_grant_type() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        exception.expect(InvalidGrantException.class);
        exception.expectMessage("Missing grant type");
        requestParameters.remove(GRANT_TYPE);
        tokenRequest.setRequestParameters(requestParameters);
        granter.validateRequest(tokenRequest);
    }

    @Test
    public void invalid_grant_type() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        exception.expect(InvalidGrantException.class);
        exception.expectMessage("Invalid grant type");
        requestParameters.put(GRANT_TYPE, "password");
        tokenRequest.setRequestParameters(requestParameters);
        granter.validateRequest(tokenRequest);
    }

    @Test
    public void get_oauth2_authentication_validates_request() {
        exception.expect(InvalidGrantException.class);
        exception.expectMessage("User authentication not found");
        granter.getOAuth2Authentication(client, tokenRequest);
        verify(granter, times(1)).validateRequest(same(tokenRequest));
    }

    @Test
    public void get_oauth2_authentication() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        OAuth2Request request = mock(OAuth2Request.class);
        when(requestFactory.createOAuth2Request(same(client), same(tokenRequest))).thenReturn(request);
        OAuth2Authentication result = granter.getOAuth2Authentication(client, tokenRequest);
        assertSame(request, result.getOAuth2Request());
        assertSame(uaaAuthentication, result.getUserAuthentication());
    }
}