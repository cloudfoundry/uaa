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
package org.cloudfoundry.identity.api.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.RestOperations;

/**
 * @author Dave Syer
 */
@OAuth2ContextConfiguration
public class AppsIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    /**
     * tests a happy-day flow of the native application profile.
     */
    @Test
    public void testHappyDay() {

        RestOperations restTemplate = serverRunning.createRestTemplate();
        ResponseEntity<String> response = restTemplate.getForEntity(serverRunning.getUrl("/api/apps"), String.class);
        // first make sure the resource is actually protected.
        assertNotSame(HttpStatus.OK, response.getStatusCode());
        HttpHeaders approvalHeaders = new HttpHeaders();
        OAuth2AccessToken accessToken = context.getAccessToken();
        approvalHeaders.set("Authorization", "bearer " + accessToken.getValue());

        ResponseEntity<String> result = serverRunning.getForString("/api/apps");
        assertEquals(HttpStatus.OK, result.getStatusCode());
        String body = result.getBody();
        assertTrue("Wrong response: " + body, body.contains("dsyerapi.cloudfoundry.com"));

    }

}
