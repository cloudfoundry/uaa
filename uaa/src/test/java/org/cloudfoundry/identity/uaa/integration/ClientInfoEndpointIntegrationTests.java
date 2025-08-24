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
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * @author Dave Syer
 */
class ClientInfoEndpointIntegrationTests {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @Test
    void getClientInfo() {
        HttpHeaders headers = new HttpHeaders();
        AuthorizationCodeResourceDetails app = testAccounts.getDefaultAuthorizationCodeResource();
        headers.set("Authorization", testAccounts.getAuthorizationHeader(app.getClientId(), app.getClientSecret()));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/clientinfo", Map.class, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("client_id", app.getClientId());
    }

    @Test
    void implicitClientInfo() {

        HttpHeaders headers = new HttpHeaders();
        ImplicitResourceDetails app = testAccounts.getDefaultImplicitResource();
        headers.set("Authorization", testAccounts.getAuthorizationHeader(app.getClientId(), ""));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/clientinfo", Map.class, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("client_id", app.getClientId());
    }

    @Test
    void unauthenticated() {

        HttpHeaders headers = new HttpHeaders();
        ResourceOwnerPasswordResourceDetails app = testAccounts.getDefaultResourceOwnerPasswordResource();
        headers.set("Authorization", testAccounts.getAuthorizationHeader(app.getClientId(), "bogus"));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/clientinfo", Map.class, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("error", "invalid_client");
    }
}
