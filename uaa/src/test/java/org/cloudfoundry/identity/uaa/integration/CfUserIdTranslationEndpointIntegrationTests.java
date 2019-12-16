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
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Integration test to verify that the userid translation use cases are
 * supported adequately for cf.
 *
 * @author Luke Taylor
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.Implicit.class)
public class CfUserIdTranslationEndpointIntegrationTests {

    private final String JOE = "joe" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String idsEndpoint = "/ids/Users";

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @BeforeOAuth2Context
    @OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
    public void setUpUserAccounts() {
        RestOperations client = serverRunning.getRestTemplate();

        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName(JOE);
        user.setName(new ScimUser.Name("Joe", "User"));
        user.addEmail("joe@blah.com");
        user.setGroups(Arrays.asList(new Group(null, "uaa.user"), new Group(null, "orgs.foo")));
        user.setVerified(true);

        String userEndpoint = "/Users";
        ResponseEntity<ScimUser> newuser = client.postForEntity(serverRunning.getUrl(userEndpoint), user,
                        ScimUser.class);

        ScimUser joe = newuser.getBody();
        assertEquals(JOE, joe.getUserName());

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("Passwo3d");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client
                        .exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                                        HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers),
                                        Void.class, joe.getId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

        // The implicit grant for cf requires extra parameters in the
        // authorization request
        context.setParameters(Collections.singletonMap("credentials",
                        testAccounts.getJsonCredentials(joe.getUserName(), "Passwo3d")));

    }

    @Before
    public void setErrorHandlerOnRestTemplate() {
        ((RestTemplate)serverRunning.getRestTemplate()).setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });
    }

    @Test
    public void findUsersWithExplicitFilterSucceeds() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(idsEndpoint + "?filter=userName eq \"" + JOE + "\"",
                        Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(1, results.get("totalResults"));
    }

    @Test
    public void findUsersExplicitEmailFails() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(idsEndpoint + "?filter=emails.value sw \"joe\"",
                        Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull("There should be an error", results.get("error"));
    }

    @Test
    public void findUsersExplicitPresentFails() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(idsEndpoint + "?filter=pr userType", Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull("There should be an error", results.get("error"));
    }

    @Test
    public void findUsersExplicitGroupFails() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(idsEndpoint + "?filter=groups.display co \"foo\"",
                        Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull("There should be an error", results.get("error"));
    }
}
