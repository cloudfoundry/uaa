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
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.token.DefaultUserAuthenticationConverter;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;

/**
 * @author Dave Syer
 */
class CheckTokenEndpointIntegrationTests {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @Test
    void decodeToken() {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        BasicCookieStore cookies = new BasicCookieStore();

        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("state", "mystateid").queryParam("client_id", resource.getClientId())
                .queryParam("redirect_uri", resource.getPreEstablishedRedirectUri()).build();
        ResponseEntity<Void> result = serverRunning.getForResponse(uri.toString(), getHeaders(cookies));
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = result.getHeaders().getLocation().toString();
        IntegrationTestUtils.extractCookies(result, cookies);

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        IntegrationTestUtils.extractCookies(response, cookies);

        // should be directed to the login screen...
        assertThat(response.getBody()).contains("/login.do")
                .contains("username")
                .contains("password");
        String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(DEFAULT_CSRF_COOKIE_NAME, csrf);

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        IntegrationTestUtils.extractCookies(result, cookies);

        response = serverRunning.getForString(result.getHeaders().getLocation().toString(), getHeaders(cookies));
        IntegrationTestUtils.extractCookies(response, cookies);

        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertThat(response.getBody()).contains("<h1>Application Authorization</h1>");

            formData.clear();
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            formData.add(USER_OAUTH_APPROVAL, "true");
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = result.getHeaders().getLocation().toString();
        } else {
            // Token cached so no need for second approval
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = response.getHeaders().getLocation().toString();
        }
        assertThat(location).as("Wrong location: " + location).matches(resource.getPreEstablishedRedirectUri() + ".*code=.+");

        formData.clear();
        formData.add("client_id", resource.getClientId());
        formData.add("redirect_uri", resource.getPreEstablishedRedirectUri());
        formData.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());

        HttpHeaders headers = new HttpHeaders();
        formData = new LinkedMultiValueMap<>();
        headers.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken.getValue());

        tokenResponse = serverRunning.postForMap("/check_token", formData, headers);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        Map<String, String> map = tokenResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());

        // Test that Spring's default converter can create an auth from the response.
        (new DefaultUserAuthenticationConverter()).extractAuthentication(map);
    }

    @Test
    void unauthorized() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", "FOO");
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/check_token", formData, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertThat(map).containsKey("error");
    }

    @Test
    void forbidden() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", "FOO");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + new String(Base64.encode("cf:".getBytes(UTF_8))));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/check_token", formData, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertThat(map).containsKey("error");
    }

    @Test
    void invalidScope() {
        OAuth2AccessToken accessToken = getAdminToken();

        String requestBody = "token=%s&scopes=%s".formatted(accessToken.getValue(), "uaa.resource%");

        HttpHeaders headers = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
        headers.set("Authorization", testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/check_token", requestBody, headers);
        System.out.println(response.getBody());
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertThat(map)
                .containsEntry("error", "parameter_parsing_error")
                .containsKey("error_description");
    }

    @Test
    void validPasswordGrant() {
        OAuth2AccessToken accessToken = getUserToken(null);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken.getValue());

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/check_token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokenResponse.getBody()).isNotNull();
        System.out.println(tokenResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = tokenResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
    }

    @Test
    void addidionalAttributes() {
        OAuth2AccessToken accessToken = getUserToken("{\"az_attr\":{\"external_group\":\"domain\\\\group1\",\"external_id\":\"abcd1234\"}}");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken.getValue());

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/check_token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokenResponse.getBody()).isNotNull();
        System.out.println(tokenResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = tokenResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
    }

    @Test
    void invalidAddidionalAttributes() {
        OAuth2AccessToken accessToken = getUserToken("{\"az_attr\":{\"external_group\":true,\"external_id\":{\"nested_group\":true,\"nested_id\":1234}} }");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken.getValue());

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/check_token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        Map<String, String> map = tokenResponse.getBody();
        assertThat(map).doesNotContainKey("az_attr");
    }

    @SuppressWarnings("unchecked")
    private OAuth2AccessToken getAdminToken() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.set("client_id", testAccounts.getAdminClientId());
        formData.set("client_secret", testAccounts.getAdminClientSecret());
        formData.set("response_type", "token");
        formData.set("grant_type", "client_credentials");

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        return DefaultOAuth2AccessToken.valueOf(response.getBody());
    }

    @SuppressWarnings("unchecked")
    private OAuth2AccessToken getUserToken(String optAdditionAttributes) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.set("client_id", "cf");
        formData.set("client_secret", "");
        formData.set("username", testAccounts.getUserName());
        formData.set("password", testAccounts.getPassword());
        formData.set("response_type", "token");
        formData.set("grant_type", "password");
        formData.set("token_format", "jwt");
        if (optAdditionAttributes != null) {
            formData.set("authorities", optAdditionAttributes);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        return DefaultOAuth2AccessToken.valueOf(response.getBody());
    }
}
