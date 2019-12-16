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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 * 
 */
public class CfAuthenticationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    private MultiValueMap<String, String> params;

    private HttpHeaders headers;

    @Before
    public void init() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        params = new LinkedMultiValueMap<String, String>();
        params.set("client_id", resource.getClientId());
        params.set("redirect_uri", resource.getRedirectUri(new DefaultAccessTokenRequest()));
        params.set("response_type", "token");
        headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    }

    @Test
    public void testDefaultScopes() {
        params.set(
                        "credentials",
                        String.format("{\"username\":\"%s\",\"password\":\"%s\"}", testAccounts.getUserName(),
                                        testAccounts.getPassword()));
        ResponseEntity<Void> response = serverRunning.postForResponse(serverRunning.getAuthorizationUri(), headers,
                        params);
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        String location = response.getHeaders().getLocation().toString();
        assertTrue("Not authenticated (no access token): " + location, location.contains("access_token"));
    }

    @Test
    public void testInvalidScopes() {
        params.set(
                        "credentials",
                        String.format("{\"username\":\"%s\",\"password\":\"%s\"}", testAccounts.getUserName(),
                                        testAccounts.getPassword()));
        params.set("scope", "read");
        ResponseEntity<Void> response = serverRunning.postForResponse(serverRunning.getAuthorizationUri(), headers,
                        params);
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        String location = response.getHeaders().getLocation().toString();
        // System.err.println(location);
        assertTrue(location.startsWith(params.getFirst("redirect_uri")));
        assertTrue(location.contains("error=invalid_scope"));
        assertFalse(location.contains("credentials="));
    }

}
