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

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.junit.Assert.assertEquals;

/**
 * @author Dave Syer
 */
public class NativeApplicationIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private ResourceOwnerPasswordResourceDetails resource;

    @Before
    public void init() {
        resource = testAccounts.getDefaultResourceOwnerPasswordResource();
    }

    /**
     * tests a happy-day flow of the Resource Owner Password Credentials grant
     * type. (formerly native application
     * profile).
     */
    @Test
    public void testHappyDay() {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("grant_type", "password");
        formData.add("username", resource.getUsername());
        formData.add("password", resource.getPassword());
        formData.add("scope", "cloud_controller.read");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization",
                        testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        ResponseEntity<String> response = serverRunning.postForString("/oauth/token", formData, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    /**
     * tests that a client secret is required.
     */
    @Test
    public void testSecretRequired() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("grant_type", "password");
        formData.add("username", resource.getUsername());
        formData.add("password", resource.getPassword());
        formData.add("scope", "cloud_controller.read");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + new String(Base64.encode("no-such-client:".getBytes(StandardCharsets.UTF_8))));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        ResponseEntity<String> response = serverRunning.postForString("/oauth/token", formData, headers);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

}
