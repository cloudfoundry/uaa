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
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests implicit grant using a direct posting of credentials to the /authorize
 * endpoint and also with an intermediate
 * form login.
 *
 * @author Dave Syer
 */
public class ImplicitTokenGrantIntegrationTests {

    private static final String REDIRECT_URL_PATTERN = "http://localhost:8080/redirect/cf#token_type=.+access_token=.+";
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private String implicitUrl() {
        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "token")
                        .queryParam("client_id", "cf")
                        .queryParam("redirect_uri", "http://localhost:8080/redirect/cf")
                        .queryParam("scope", "cloud_controller.read").build();
        return uri.toString();
    }

    @Test
    public void authzViaJsonEndpointFailsWithHttpGet() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        String credentials = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", testAccounts.getUserName(),
                        testAccounts.getPassword());

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl() + "&credentials={credentials}",
                        headers, credentials);

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());

    }

    @Test
    public void authzViaJsonEndpointSucceedsWithCorrectCredentials() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", testAccounts.getUserName(),
                        testAccounts.getPassword());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("credentials", credentials);
        ResponseEntity<Void> result = serverRunning.postForResponse(implicitUrl(), headers, formData);

        assertNotNull(result.getHeaders().getLocation());
        assertTrue(result.getHeaders().getLocation().toString()
            .matches(REDIRECT_URL_PATTERN));

    }

    @Test
    public void authzViaJsonEndpointSucceedsWithAcceptForm() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_FORM_URLENCODED));

        String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", testAccounts.getUserName(),
                        testAccounts.getPassword());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("credentials", credentials);
        ResponseEntity<Void> result = serverRunning.postForResponse(implicitUrl(), headers, formData);

        URI location = result.getHeaders().getLocation();
        assertNotNull(location);
        assertTrue("Wrong location: " + location, location.toString()
            .matches(REDIRECT_URL_PATTERN));

    }

    @Test
    public void authzWithIntermediateFormLoginSucceeds() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl(), headers);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }

        ResponseEntity<String> response = serverRunning.getForString(location, headers);
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String c : response.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", c);
            }
        }
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));


        location = "/login.do";

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));

        result = serverRunning.postForRedirect(location, headers, formData);

        // System.err.println(result.getStatusCode());
        // System.err.println(result.getHeaders());

        assertNotNull(result.getHeaders().getLocation());
        assertTrue(result.getHeaders().getLocation().toString()
            .matches(REDIRECT_URL_PATTERN));
    }

}
