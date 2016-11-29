/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import static org.cloudfoundry.identity.uaa.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.web.CookieBasedCsrfTokenRepository;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
@RunWith(Parameterized.class)
public class AuthorizationCodeGrantIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Parameters
    public static List<Object[]> parameters() {
        // Make it run twice to test cached approvals
        return Arrays.asList(new Object[0], new Object[0]);
    }

    @Test
    public void testSuccessfulAuthorizationCodeFlow() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        // TODO: should be able to handle just TEXT_HTML
        headers.setAccept(Arrays.asList(MediaType.TEXT_HTML, MediaType.ALL));

        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "code")
                        .queryParam("state", "mystateid").queryParam("client_id", resource.getClientId())
                        .queryParam("redirect_uri", resource.getPreEstablishedRedirectUri()).build();
        ResponseEntity<Void> result = serverRunning.getForResponse(uri.toString(), headers);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }


        ResponseEntity<String> response = serverRunning.getForString(location, headers);

        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }

        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());
        formData.add(DEFAULT_CSRF_COOKIE_NAME, csrf);
        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", headers, formData);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        headers.remove("Cookie");
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }

        response = serverRunning.getForString(result.getHeaders().getLocation().toString(), headers);
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            result = serverRunning.postForResponse("/oauth/authorize", headers, formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = result.getHeaders().getLocation().toString();
        }
        else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = response.getHeaders().getLocation().toString();
        }
        assertTrue("Wrong location: " + location,
                        location.matches(resource.getPreEstablishedRedirectUri() + ".*code=.+"));

        formData.clear();
        formData.add("client_id", resource.getClientId());
        formData.add("redirect_uri", resource.getPreEstablishedRedirectUri());
        formData.add("grant_type", "authorization_code");
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization",
                        testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> body = tokenResponse.getBody();
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"aud\""));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"user_id\""));
    }
}
