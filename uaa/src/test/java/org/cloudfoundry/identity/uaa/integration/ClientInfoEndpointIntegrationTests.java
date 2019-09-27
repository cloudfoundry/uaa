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
package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;

/**
 * @author Dave Syer
 */
public class ClientInfoEndpointIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Test
    public void testGetClientInfo() {

        HttpHeaders headers = new HttpHeaders();
        AuthorizationCodeResourceDetails app = testAccounts.getDefaultAuthorizationCodeResource();
        headers.set("Authorization", testAccounts.getAuthorizationHeader(app.getClientId(), app.getClientSecret()));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/clientinfo", Map.class, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(app.getClientId(), response.getBody().get("client_id"));

    }

    @Test
    public void testImplicitClientInfo() {

        HttpHeaders headers = new HttpHeaders();
        ImplicitResourceDetails app = testAccounts.getDefaultImplicitResource();
        headers.set("Authorization", testAccounts.getAuthorizationHeader(app.getClientId(), ""));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/clientinfo", Map.class, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(app.getClientId(), response.getBody().get("client_id"));

    }

    @Test
    public void testUnauthenticated() {

        HttpHeaders headers = new HttpHeaders();
        ResourceOwnerPasswordResourceDetails app = testAccounts.getDefaultResourceOwnerPasswordResource();
        headers.set("Authorization", testAccounts.getAuthorizationHeader(app.getClientId(), "bogus"));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/clientinfo", Map.class, headers);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("unauthorized", response.getBody().get("error"));

    }

}
