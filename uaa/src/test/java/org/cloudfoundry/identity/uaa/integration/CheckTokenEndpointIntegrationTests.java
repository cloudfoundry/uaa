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
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.util.Arrays;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;

/**
 * @author Dave Syer
 */
public class CheckTokenEndpointIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Test
    public void testDecodeToken() throws Exception {

        // TODO Fix to use json API rather than HTML
        // TODO: should be able to handle just TEXT_HTML

        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        BasicCookieStore cookies = new BasicCookieStore();

        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "code")
                        .queryParam("state", "mystateid").queryParam("client_id", resource.getClientId())
                        .queryParam("redirect_uri", resource.getPreEstablishedRedirectUri()).build();
        ResponseEntity<Void> result = serverRunning.getForResponse(uri.toString(), getHeaders(cookies));
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
        String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(DEFAULT_CSRF_COOKIE_NAME, csrf);

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }

        response = serverRunning.getForString(result.getHeaders().getLocation().toString(), getHeaders(cookies));
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            formData.add(USER_OAUTH_APPROVAL, "true");
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
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

        HttpHeaders headers = new HttpHeaders();
        formData = new LinkedMultiValueMap<String, String>();
        headers.set("Authorization",
                        testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken.getValue());

        tokenResponse = serverRunning.postForMap("/check_token", formData, headers);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        //System.err.println(tokenResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = tokenResponse.getBody();
        assertNotNull(map.get("iss"));
        assertEquals(testAccounts.getUserName(), map.get("user_name"));
        assertEquals(testAccounts.getEmail(), map.get("email"));

        // Test that Spring's default converter can create an auth from the response.
        Authentication auth = (new DefaultUserAuthenticationConverter()).extractAuthentication(map);
    }

    @Test
    public void testTokenKey() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app",
                        "appclientsecret");
        headers.set("Authorization",
                        testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject("/token_key", Map.class, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        // System.err.println(map);
        assertNotNull(map.get("alg"));
        assertNotNull(map.get("value"));

    }

    @Test
    public void testUnauthorized() throws Exception {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("token", "FOO");
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/check_token", formData, headers);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertTrue(map.containsKey("error"));

    }

    @Test
    public void testForbidden() throws Exception {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("token", "FOO");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + new String(Base64.encode("cf:".getBytes("UTF-8"))));
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/check_token", formData, headers);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertTrue(map.containsKey("error"));

    }

}
