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

package org.cloudfoundry.identity.uaa.oauth;

import static java.util.Collections.singleton;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.user.UaaUserApprovalHandler;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

/**
 * @author Dave Syer
 * 
 */
public class UaaUserApprovalHandlerTests {

    private UaaUserApprovalHandler handler = new UaaUserApprovalHandler();

    private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);

    private AuthorizationServerTokenServices tokenServices = Mockito.mock(AuthorizationServerTokenServices.class);

    private AuthorizationRequest authorizationRequest = new AuthorizationRequest("client",Arrays.asList("read"));

    private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("joe", "", AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));

    {
        handler.setClientDetailsService(clientDetailsService);
        handler.setTokenServices(tokenServices);
    }

    @Test
    public void testNotAutoApprove() {
        BaseClientDetails client = new BaseClientDetails("client", "none", "read,write", "authorization_code",
                        "uaa.none");
        Mockito.when(clientDetailsService.loadClientByClientId("client")).thenReturn(client);
        assertFalse(handler.isApproved(authorizationRequest, userAuthentication));
    }

    @Test
    public void testAutoApproveAll() {
        BaseClientDetails client = new BaseClientDetails("client", "none", "read,write", "authorization_code",
                        "uaa.none");
        client.setAutoApproveScopes(singleton("true"));
            Mockito.when(clientDetailsService.loadClientByClientId("client")).thenReturn(client);
        assertTrue(handler.isApproved(authorizationRequest, userAuthentication));
    }

    @Test
    public void testAutoApproveByScope() {
        BaseClientDetails client = new BaseClientDetails("client", "none", "read,write", "authorization_code",
                        "uaa.none");
        Mockito.when(clientDetailsService.loadClientByClientId("client")).thenReturn(client);
        client.setAutoApproveScopes(singleton("read"));
        assertTrue(handler.isApproved(authorizationRequest, userAuthentication));
        client.setAutoApproveScopes(singleton("write"));
        assertFalse(handler.isApproved(authorizationRequest, userAuthentication));
    }


}
