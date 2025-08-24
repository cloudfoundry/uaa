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
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.springframework.http.MediaType.APPLICATION_JSON;

/**
 * @author Dave Syer
 */
class RefreshTokenSupportIntegrationTests {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @Test
    void tokenRefreshedCorrectFlow() {
        BasicCookieStore cookies = new BasicCookieStore();

        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

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

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        cookies.clear();
        IntegrationTestUtils.extractCookies(result, cookies);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        response = serverRunning.getForString(result.getHeaders().getLocation().toString(), getHeaders(cookies));
        IntegrationTestUtils.extractCookies(response, cookies);

        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertThat(response.getBody()).contains("<h1>Application Authorization</h1>");

            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
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
        tokenHeaders.set("Cache-Control", "no-store");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());

        // get the refresh token
        formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "refresh_token");
        formData.add("refresh_token", accessToken.getRefreshToken().getValue());
        tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokenResponse.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
        @SuppressWarnings("unchecked")
        OAuth2AccessToken newAccessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());
        assertThatNoException().as("Refreshed token was not a JWT")
                .isThrownBy(() -> JwtHelper.decode(newAccessToken.getValue()));
        assertThat(accessToken.getValue()).as("New access token should be different to the old one.").isNotEqualTo(newAccessToken.getValue());
    }

    @Test
    void refreshTokenWithNonExistingZone() {
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "refresh_token");
        formData.add("refresh_token", "dummyrefreshtoken-r");
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap(serverRunning.getAccessTokenUri().replace("localhost", "testzonedoesnotexist.localhost"), formData, new HttpHeaders());
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void refreshTokenWithInactiveZone() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");

        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "refresh_token");
        formData.add("refresh_token", "dummyrefreshtoken-r");
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap(serverRunning.getAccessTokenUri().replace("localhost", "testzoneinactive.localhost"), formData, new HttpHeaders());
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void userLoginViaPasswordGrantAndRefreshUsingClientWithEmptyClientSecret() {
        ResponseEntity<String> responseEntity = PasswordGrantIntegrationTests.makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), "cf", "", serverRunning.getAccessTokenUri());
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        String refreshToken = PasswordGrantIntegrationTests.validateClientAuthenticationMethod(responseEntity, true);
        responseEntity = makeRefreshGrantRequest(refreshToken, "cf", "", serverRunning.getAccessTokenUri());
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        PasswordGrantIntegrationTests.validateClientAuthenticationMethod(responseEntity, true);
    }

    @Test
    void userLoginViaPasswordGrantAndRefreshUsingConfidentialClient() {
        ResponseEntity<String> responseEntity = PasswordGrantIntegrationTests.makePasswordGrantRequest(testAccounts.getUserName(), testAccounts.getPassword(), "app", "appclientsecret", serverRunning.getAccessTokenUri());
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        String refreshToken = PasswordGrantIntegrationTests.validateClientAuthenticationMethod(responseEntity, false);
        responseEntity = makeRefreshGrantRequest(refreshToken, "app", "appclientsecret", serverRunning.getAccessTokenUri());
        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        PasswordGrantIntegrationTests.validateClientAuthenticationMethod(responseEntity, false);
    }

    protected static ResponseEntity<String> makeRefreshGrantRequest(String refreshToken, String clientId, String clientSecret, String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(APPLICATION_JSON));
        headers.add("Authorization", UaaTestAccounts.getAuthorizationHeader(clientId, clientSecret));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        RestTemplate template = PasswordGrantIntegrationTests.getRestTemplate();
        return template.postForEntity(url, request, String.class);
    }
}
