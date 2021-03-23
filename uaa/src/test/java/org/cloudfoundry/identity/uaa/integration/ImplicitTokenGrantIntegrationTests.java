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

import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
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
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CsrfPostProcessor.CSRF_PARAMETER_NAME;
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
    public void authzViaJsonEndpointFailsWithHttpGet() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        String credentials = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", testAccounts.getUserName(),
                        testAccounts.getPassword());

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl() + "&credentials={credentials}",
                        headers, credentials);

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());

    }

    @Test
    public void authzViaJsonEndpointSucceedsWithCorrectCredentials() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

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
    public void authzViaJsonEndpointSucceedsWithAcceptForm() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED));

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
    public void authzWithIntermediateFormLoginSucceeds() {

        BasicCookieStore cookies = new BasicCookieStore();

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl(), getHeaders(cookies));
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
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
        formData.add(CSRF_PARAMETER_NAME, IntegrationTestUtils.extracCsrfToken(response.getBody()));

        result = serverRunning.postForRedirect(location, getHeaders(cookies), formData);

        // System.err.println(result.getStatusCode());
        // System.err.println(result.getHeaders());

        assertNotNull(result.getHeaders().getLocation());
        assertTrue(result.getHeaders().getLocation().toString()
            .matches(REDIRECT_URL_PATTERN));
    }

    @Test
    public void authzWithNonExistingIdentityZone() {
        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl().replace("localhost", "testzonedoesnotexist.localhost"), new HttpHeaders());
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    public void authzWithInactiveIdentityZone() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");

        ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl().replace("localhost", "testzoneinactive.localhost"), new HttpHeaders());
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }
}
