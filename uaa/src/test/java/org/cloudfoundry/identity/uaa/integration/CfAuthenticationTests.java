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
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 */
class CfAuthenticationTests {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    private MultiValueMap<String, String> params;

    private HttpHeaders headers;

    @BeforeEach
    void init() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        params = new LinkedMultiValueMap<>();
        params.set("client_id", resource.getClientId());
        params.set("redirect_uri", resource.getRedirectUri(new DefaultAccessTokenRequest()));
        params.set("response_type", "token");
        headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    }

    @Test
    void defaultScopes() {
        params.set(
                "credentials",
                "{\"username\":\"%s\",\"password\":\"%s\"}".formatted(testAccounts.getUserName(),
                        testAccounts.getPassword()));
        ResponseEntity<Void> response = serverRunning.postForResponse(serverRunning.getAuthorizationUri(), headers,
                params);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = response.getHeaders().getLocation().toString();
        assertThat(location).as("Not authenticated (no access token): " + location).contains("access_token");
    }

    @Test
    void invalidScopes() {
        params.set(
                "credentials",
                "{\"username\":\"%s\",\"password\":\"%s\"}".formatted(testAccounts.getUserName(),
                        testAccounts.getPassword()));
        params.set("scope", "read");
        ResponseEntity<Void> response = serverRunning.postForResponse(serverRunning.getAuthorizationUri(), headers,
                params);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = response.getHeaders().getLocation().toString();
        assertThat(location).startsWith(params.getFirst("redirect_uri"))
                .contains("error=invalid_scope")
                .doesNotContain("credentials=");
    }
}
