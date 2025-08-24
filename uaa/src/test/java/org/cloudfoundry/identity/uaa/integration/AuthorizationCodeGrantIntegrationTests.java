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
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
class AuthorizationCodeGrantIntegrationTests {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @Test
    void successfulAuthorizationCodeFlow() {
        successfulAuthorizationCodeFlow_Internal();
        successfulAuthorizationCodeFlow_Internal();
    }

    @Test
    void successfulAuthorizationCodeFlowWithPkceS256() throws Exception {
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE,
                UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE,
                UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
    }

    @Test
    void successfulAuthorizationCodeFlowWithPkcePlain() throws Exception {
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_CHALLENGE);
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_CHALLENGE);
    }

    @Test
    void pkcePlainWithWrongCodeVerifier() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_VERIFIER);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error")).contains("invalid_grant");
        assertThat(body.get("error_description")).contains("Invalid code verifier");
    }

    @Test
    void pkceS256WithWrongCodeVerifier() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_CHALLENGE);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error")).contains("invalid_grant");
        assertThat(body.get("error_description")).contains("Invalid code verifier");
    }

    @Test
    void missingCodeChallenge() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest("", UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error")).contains("invalid_grant");
        assertThat(body.get("error_description")).contains("PKCE error: Code verifier not required for this authorization code.");
    }

    @Test
    void missingCodeVerifier() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, "");
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error")).contains("invalid_grant");
        assertThat(body.get("error_description")).contains("PKCE error: Code verifier must be provided for this authorization code.");
    }

    @Test
    void invalidCodeChallenge() throws Exception {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        String responseLocation = IntegrationTestUtils.getAuthorizationResponse(serverRunning,
                resource.getClientId(),
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                resource.getPreEstablishedRedirectUri(),
                "ShortCodeChallenge",
                UaaTestAccounts.CODE_CHALLENGE_METHOD_S256);
        assertThat(responseLocation).contains("Code challenge length must between 43 and 128 and use only [A-Z],[a-z],[0-9],_,.,-,~ characters.");
    }

    @Test
    void invalidCodeVerifier() {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        ResponseEntity<Map> tokenResponse = IntegrationTestUtils.getTokens(serverRunning,
                resource.getClientId(),
                resource.getClientSecret(),
                resource.getPreEstablishedRedirectUri(),
                "invalidCodeVerifier",
                "authorizationCode");
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error")).contains("invalid_request");
        assertThat(body.get("error_description")).contains("Code verifier length must");
    }

    @Test
    void unsupportedCodeChallengeMethod() throws Exception {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        String responseLocation = IntegrationTestUtils.getAuthorizationResponse(serverRunning,
                resource.getClientId(),
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                resource.getPreEstablishedRedirectUri(),
                UaaTestAccounts.CODE_CHALLENGE,
                "UnsupportedCodeChallengeMethod");
        assertThat(responseLocation).contains("Unsupported code challenge method.");
    }

    @Test
    void zoneDoesNotExist() {
        ServerRunningExtension.UriBuilder builder = serverRunning.buildUri(serverRunning.getAuthorizationUri().replace("localhost", "testzonedoesnotexist.localhost"))
                .queryParam("response_type", "code")
                .queryParam("state", "mystateid")
                .queryParam("client_id", "clientId")
                .queryParam("redirect_uri", "http://localhost:8080/uaa");

        URI uri = builder.build();

        ResponseEntity<Void> result =
                serverRunning.createRestTemplate().exchange(
                        uri.toString(),
                        HttpMethod.GET,
                        new HttpEntity<>(null, new HttpHeaders()),
                        Void.class
                );
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void zoneInactive() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");
        ServerRunningExtension.UriBuilder builder = serverRunning.buildUri(serverRunning.getAuthorizationUri().replace("localhost", "testzoneinactive.localhost"))
                .queryParam("response_type", "code")
                .queryParam("state", "mystateid")
                .queryParam("client_id", "clientId")
                .queryParam("redirect_uri", "http://localhost:8080/uaa");

        URI uri = builder.build();

        ResponseEntity<Void> result =
                serverRunning.createRestTemplate().exchange(
                        uri.toString(),
                        HttpMethod.GET,
                        new HttpEntity<>(null, new HttpHeaders()),
                        Void.class
                );
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void authorizationRequestWithoutRedirectUri() {

        Map<String, String> body = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                "login",
                "loginsecret",
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                null,
                null,
                null,
                null,
                false);
        assertThat(body).as("Token not received").containsKey("access_token");

        try {
            IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning, "app", "appclientsecret",
                    testAccounts.getUserName(), testAccounts.getPassword(),
                    null, null, null, null, false);
        } catch (AssertionError error) {
            // expected
            return;
        }
        fail("Token retrival not allowed");
    }

    public void successfulAuthorizationCodeFlow_Internal() {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

        Map<String, String> body = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                testAccounts,
                resource.getClientId(),
                resource.getClientSecret(),
                testAccounts.getUserName(),
                testAccounts.getPassword());
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertThat(token.getClaims()).as("Wrong claims: " + token.getClaims()).contains("\"aud\"")
                .as("Wrong claims: " + token.getClaims()).contains("\"user_id\"");
    }

    private void testAuthorizationCodeFlowWithPkce_Internal(String codeChallenge, String codeChallengeMethod, String codeVerifier) throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(codeChallenge, codeChallengeMethod, codeVerifier);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<String, String> body = tokenResponse.getBody();
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertThat(token.getClaims()).as("Wrong claims: " + token.getClaims()).contains("\"aud\"")
                .as("Wrong claims: " + token.getClaims()).contains("\"user_id\"");
        IntegrationTestUtils.callCheckToken(serverRunning,
                body.get("access_token"),
                testAccounts.getDefaultAuthorizationCodeResource().getClientId(),
                testAccounts.getDefaultAuthorizationCodeResource().getClientSecret());
    }

    private ResponseEntity<Map> doAuthorizeAndTokenRequest(String codeChallenge, String codeChallengeMethod, String codeVerifier) throws Exception {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        String authorizationResponse = IntegrationTestUtils.getAuthorizationResponse(serverRunning,
                resource.getClientId(),
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                resource.getPreEstablishedRedirectUri(),
                codeChallenge,
                codeChallengeMethod);
        String authorizationCode = authorizationResponse.split("code=")[1].split("&")[0];
        return IntegrationTestUtils.getTokens(serverRunning,
                resource.getClientId(),
                resource.getClientSecret(),
                resource.getPreEstablishedRedirectUri(),
                codeVerifier,
                authorizationCode);
    }
}
