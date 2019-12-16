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
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2ErrorHandler;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
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
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Integration test to verify that the trusted client use cases are supported
 * adequately for cf.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.Implicit.class)
public class CfScimUserEndpointIntegrationTests {

    private final String JOE = "joe" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String usersEndpoint = "/Users";

    private ScimUser joe;

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
        user.setVerified(true);
        user.setPassword("Passwo3d124!");

        ResponseEntity<ScimUser> newuser = client.postForEntity(serverRunning.getUrl(usersEndpoint), user,
                        ScimUser.class);

        joe = newuser.getBody();
        assertEquals(JOE, joe.getUserName());

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("Passwo3d");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client
                        .exchange(serverRunning.getUrl(usersEndpoint) + "/{id}/password",
                                        HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers),
                                        Void.class, joe.getId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

        // The implicit grant for cf requires extra parameters in the
        // authorization request
        context.setParameters(Collections.singletonMap("credentials",
                        testAccounts.getJsonCredentials(joe.getUserName(), "Passwo3d")));

    }

    @Before
    public void setUp() {
        ((RestTemplate)serverRunning.getRestTemplate()).setErrorHandler(
            new UaaOauth2ErrorHandler(context.getResource(), HttpStatus.Series.SERVER_ERROR)
        );
    }

    @SuppressWarnings("rawtypes")
    private ResponseEntity<Map> deleteUser(RestOperations client, String id, int version) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "\"" + version + "\"");
        return client.exchange(serverRunning.getUrl(usersEndpoint + "/{id}"), HttpMethod.DELETE, new HttpEntity<Void>(
                        headers), Map.class, id);
    }

    @Test
    public void changePasswordSucceeds() {

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("Passwo3d");
        change.setPassword("Newpasswo3d");

        HttpHeaders headers = new HttpHeaders();
        RestOperations client = serverRunning.getRestTemplate();
        ResponseEntity<Void> result = client
                        .exchange(serverRunning.getUrl(usersEndpoint) + "/{id}/password",
                                        HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers),
                                        Void.class, joe.getId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

    }

    @Test
    public void userInfoSucceeds() {

        HttpHeaders headers = new HttpHeaders();
        RestOperations client = serverRunning.getRestTemplate();
        ResponseEntity<Void> result = client.exchange(serverRunning.getUrl("/userinfo"), HttpMethod.GET,
                        new HttpEntity<Void>(null, headers), Void.class, joe.getId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

    }

    @Test
    public void deleteUserFails() {
        RestOperations client = serverRunning.getRestTemplate();
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = deleteUser(client, joe.getId(), joe.getVersion());
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> error = response.getBody();
        // System.err.println(error);
        assertEquals("insufficient_scope", error.get("error"));
    }

    @Test
    public void findUsersFails() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertNotNull("There should be an error", results.get("error"));
    }

}
