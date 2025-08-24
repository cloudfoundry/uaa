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
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 */
class PasswordChangeEndpointIntegrationTests {

    private final String JOE = "joe_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String userEndpoint = "/Users";

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @RegisterExtension
    private static final OAuth2ContextExtension context = OAuth2ContextExtension.withTestAccounts(serverRunning, testAccountExtension);

    private RestOperations client;

    private ScimUser joe;

    private ResponseEntity<ScimUser> createUser(String username, String firstName, String lastName, String email) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setPassword("pas5Word");
        user.setVerified(true);
        return client.postForEntity(serverRunning.getUrl(userEndpoint), user, ScimUser.class);
    }

    @BeforeEach
    void createRestTemplate() {
        client = serverRunning.getRestTemplate();
        ((RestTemplate) serverRunning.getRestTemplate()).setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // pass through
            }
        });
    }

    @BeforeOAuth2Context
    @OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
    public void createAccount() {
        client = serverRunning.getRestTemplate();
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
        joe = response.getBody();
        assertThat(joe.getUserName()).isEqualTo(JOE);
    }

    // curl -v -H "Content-Type: application/json" -X PUT -H
    // "Accept: application/json" --data
    // "{\"password\":\"newpassword\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}"
    // http://localhost:8080/uaa/User/{id}/password
    @Test
    @OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
    void changePasswordSucceeds() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("Newpasswo3d");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client
                .exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                        HttpMethod.PUT, new HttpEntity<>(change, headers),
                        Void.class, joe.getId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
    void changePasswordSameAsOldFails() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("pas5Word");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client
                .exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                        HttpMethod.PUT, new HttpEntity<>(change, headers),
                        Void.class, joe.getId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @Test
    @OAuth2ContextConfiguration(resource = OAuth2ContextConfiguration.Implicit.class, initialize = false)
    void userChangesOwnPassword() {

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set("source", "credentials");
        parameters.set("username", joe.getUserName());
        parameters.set("password", "pas5Word");
        context.getAccessTokenRequest().putAll(parameters);

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("pas5Word");
        change.setPassword("Newpasswo3d");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client
                .exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                        HttpMethod.PUT, new HttpEntity<>(change, headers),
                        Void.class, joe.getId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @OAuth2ContextConfiguration(resource = OAuth2ContextConfiguration.Implicit.class, initialize = false)
    void userMustSupplyOldPassword() {

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set("source", "credentials");
        parameters.set("username", joe.getUserName());
        parameters.set("password", "pas5Word");
        context.getAccessTokenRequest().putAll(parameters);

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("Newpasswo3d");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client
                .exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                        HttpMethod.PUT, new HttpEntity<>(change, headers),
                        Void.class, joe.getId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @OAuth2ContextConfiguration(resource = OAuth2ContextConfiguration.ClientCredentials.class, initialize = false)
    void userAccountGetsUnlockedAfterPasswordChange() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization",
                testAccounts.getAuthorizationHeader("app", "appclientsecret"));

        MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
        data.put("grant_type", Collections.singletonList("password"));
        data.put("username", Collections.singletonList(joe.getUserName()));
        data.put("password", Collections.singletonList("pas5Word"));

        ResponseEntity<Map> result = serverRunning.postForMap(
                serverRunning.buildUri("/oauth/token").build().toString(), data, headers);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Lock out the account
        data.put("password", Collections.singletonList("randomPassword1"));

        for (int i = 0; i < 5; i++) {
            result = serverRunning.postForMap(serverRunning.buildUri("/oauth/token").build().toString(), data, headers);
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        // Check that it is locked
        result = serverRunning.postForMap(serverRunning.buildUri("/oauth/token").build().toString(), data, headers);
        assertThat(result.getBody()).containsEntry("error_description", "Your account has been locked because of too many failed attempts to login.");
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("Newpasswo3d");

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set("grant_type", "client_credentials");
        parameters.set("username", "admin");
        parameters.set("password", "adminsecret");
        context.getAccessTokenRequest().putAll(parameters);

        // Change the password
        HttpHeaders passwordChangeHeaders = new HttpHeaders();
        ResponseEntity<Void> passwordChangeResult = client.exchange(serverRunning.getUrl(userEndpoint)
                        + "/{id}/password",
                HttpMethod.PUT, new HttpEntity<>(change, passwordChangeHeaders),
                Void.class, joe.getId());
        assertThat(passwordChangeResult.getStatusCode()).isEqualTo(HttpStatus.OK);

        MultiValueMap<String, String> newData = new LinkedMultiValueMap<>();
        newData.put("grant_type", Collections.singletonList("password"));
        newData.put("username", Collections.singletonList(joe.getUserName()));
        newData.put("password", Collections.singletonList("Newpasswo3d"));

        ResponseEntity<Map> updatedResult = serverRunning.postForMap(serverRunning.buildUri("/oauth/token").build()
                .toString(), newData, headers);
        assertThat(updatedResult.getStatusCode()).isEqualTo(HttpStatus.OK);

    }
}
