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

import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;

/**
 * Tests implicit grant using a direct posting of credentials to the /authorize
 * endpoint and also with an intermediate
 * form login.
 *
 * @author Dave Syer
 */
class ImplicitTokenGrantIntegrationTests {

    private static final String REDIRECT_URL_PATTERN = "http://localhost:8080/redirect/cf#token_type=.+access_token=.+";

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    private String implicitUrl() {
        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "token")
                .queryParam("client_id", "cf")
                .queryParam("redirect_uri", "http://localhost:8080/redirect/cf")
                .queryParam("scope", "cloud_controller.read").build();
        return uri.toString();
    }

    @Test
    void authzViaJsonEndpointFailsWithHttpGet() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        String credentials = "{\"username\":\"%s\",\"password\":\"%s\"}".formatted(testAccounts.getUserName(),
                testAccounts.getPassword());

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl() + "&credentials={credentials}",
                headers, credentials);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

    }

    @Test
    void authzViaJsonEndpointSucceedsWithCorrectCredentials() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        String credentials = "{ \"username\":\"%s\", \"password\":\"%s\" }".formatted(testAccounts.getUserName(),
                testAccounts.getPassword());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("credentials", credentials);
        ResponseEntity<Void> result = serverRunning.postForResponse(implicitUrl(), headers, formData);

        assertThat(result.getHeaders().getLocation()).isNotNull();
        assertThat(result.getHeaders().getLocation().toString()).matches(REDIRECT_URL_PATTERN);
    }

    @Test
    void authzViaJsonEndpointSucceedsWithAcceptForm() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED));

        String credentials = "{ \"username\":\"%s\", \"password\":\"%s\" }".formatted(testAccounts.getUserName(),
                testAccounts.getPassword());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("credentials", credentials);
        ResponseEntity<Void> result = serverRunning.postForResponse(implicitUrl(), headers, formData);

        URI location = result.getHeaders().getLocation();
        assertThat(location).isNotNull();
        assertThat(location.toString()).as("Wrong location: " + location).matches(REDIRECT_URL_PATTERN);
    }

    @Test
    void authzWithIntermediateFormLoginSucceeds() {
        BasicCookieStore cookies = new BasicCookieStore();

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl(), getHeaders(cookies));
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = result.getHeaders().getLocation().toString();
        IntegrationTestUtils.extractCookies(result, cookies);

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        IntegrationTestUtils.extractCookies(response, cookies);

        // should be directed to the login screen...
        assertThat(response.getBody()).contains("/login.do")
                .contains("username")
                .contains("password");

        location = "/login.do";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));

        result = serverRunning.postForRedirect(location, getHeaders(cookies), formData);

        assertThat(result.getHeaders().getLocation()).isNotNull();
        assertThat(result.getHeaders().getLocation().toString()).matches(REDIRECT_URL_PATTERN);
    }

    @Test
    void authzWithNonExistingIdentityZone() {
        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl().replace("localhost", "testzonedoesnotexist.localhost"), new HttpHeaders());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void authzWithInactiveIdentityZone() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl().replace("localhost", "testzoneinactive.localhost"), new HttpHeaders());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
