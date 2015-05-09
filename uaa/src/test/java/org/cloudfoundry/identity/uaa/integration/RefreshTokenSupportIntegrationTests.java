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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class RefreshTokenSupportIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private ResourceOwnerPasswordResourceDetails resource;

    @Before
    public void init() {
        resource = testAccounts.getDefaultResourceOwnerPasswordResource();

    }

    @Test
    public void testTokenRefreshedCorrectFlow() throws Exception {
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
            String cookie = result.getHeaders().getFirst("Set-Cookie");
            headers.set("Cookie", cookie);
        }

        ResponseEntity<String> response = serverRunning.getForString(location, headers);
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", headers, formData);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        if (result.getHeaders().containsKey("Set-Cookie")) {
            String cookie = result.getHeaders().getFirst("Set-Cookie");
            headers.set("Cookie", cookie);
        }

        response = serverRunning.getForString(result.getHeaders().getLocation().toString(), headers);
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add("user_oauth_approval", "true");
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
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());

        // get the refresh token
        formData = new LinkedMultiValueMap<String, String>();
        formData.add("grant_type", "refresh_token");
        formData.add("refresh_token", accessToken.getRefreshToken().getValue());
        tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        assertEquals("no-cache, no-store, max-age=0, must-revalidate", tokenResponse.getHeaders().getFirst("Cache-Control"));
        @SuppressWarnings("unchecked")
        OAuth2AccessToken newAccessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());
        try {
            JwtHelper.decode(newAccessToken.getValue());
        } catch (IllegalArgumentException e) {
            fail("Refreshed token was not a JWT");
        }
        assertFalse("New access token should be different to the old one.",
                        newAccessToken.getValue().equals(accessToken.getValue()));

    }

}
