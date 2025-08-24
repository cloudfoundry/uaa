/*
 * *****************************************************************************
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

import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.test.BeforeOAuth2Context;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextExtension;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test to verify that the trusted client use cases are supported
 * adequately for cf.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.Implicit.class)
class CfScimUserEndpointIntegrationTests {

    private final String JOE = "joe" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String usersEndpoint = "/Users";

    private ScimUser joe;

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @RegisterExtension
    private static final OAuth2ContextExtension context = OAuth2ContextExtension.withTestAccounts(serverRunning, testAccountExtension);

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
        assertThat(joe.getUserName()).isEqualTo(JOE);

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("Passwo3d");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client
                .exchange(serverRunning.getUrl(usersEndpoint) + "/{id}/password",
                        HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers),
                        Void.class, joe.getId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

        // The implicit grant for cf requires extra parameters in the
        // authorization request
        context.setParameters(Collections.singletonMap("credentials",
                testAccounts.getJsonCredentials(joe.getUserName(), "Passwo3d")));

    }

    @BeforeEach
    void setUp() {
        ((RestTemplate) serverRunning.getRestTemplate()).setErrorHandler(
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
    void changePasswordSucceeds() {

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("Passwo3d");
        change.setPassword("Newpasswo3d");

        HttpHeaders headers = new HttpHeaders();
        RestOperations client = serverRunning.getRestTemplate();
        ResponseEntity<Void> result = client
                .exchange(serverRunning.getUrl(usersEndpoint) + "/{id}/password",
                        HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers),
                        Void.class, joe.getId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

    }

    @Test
    void userInfoSucceeds() {

        HttpHeaders headers = new HttpHeaders();
        RestOperations client = serverRunning.getRestTemplate();
        ResponseEntity<Void> result = client.exchange(serverRunning.getUrl("/userinfo"), HttpMethod.GET,
                new HttpEntity<Void>(null, headers), Void.class, joe.getId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

    }

    @Test
    void deleteUserFails() {
        RestOperations client = serverRunning.getRestTemplate();
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = deleteUser(client, joe.getId(), joe.getVersion());
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        @SuppressWarnings("unchecked")
        Map<String, String> error = response.getBody();
        assertThat(error).containsEntry("error", "insufficient_scope");
    }

    @Test
    void findUsersFails() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(results).as("There should be an error").containsKey("error");
    }
}
