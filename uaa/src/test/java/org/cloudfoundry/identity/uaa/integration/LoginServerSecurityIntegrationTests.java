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

import org.apache.commons.codec.binary.Base64;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.test.BeforeOAuth2Context;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextExtension;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;

/**
 * Integration test to verify that the Login Server authentication channel is
 * open and working.
 *
 * @author Dave Syer
 */
@TestMethodOrder(MethodOrderer.MethodName.class)
class LoginServerSecurityIntegrationTests {

    private final String JOE = "joe" + new RandomValueStringGenerator().generate().toLowerCase();
    private final String loginServerJoe = "ls_joe" + new RandomValueStringGenerator().generate().toLowerCase();
    private ScimUser joe;

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @RegisterExtension
    private static final OAuth2ContextExtension context = OAuth2ContextExtension.withTestAccounts(serverRunning, testAccountExtension);

    private final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    private final HttpHeaders headers = new HttpHeaders();
    private ScimUser userForLoginServer;

    @BeforeEach
    void init() {
        params.set("source", "login");
        params.set("redirect_uri", "http://localhost:8080/app/");
        params.set("response_type", "token");
        if (joe != null) {
            params.set("username", joe.getUserName());
        }
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ((RestTemplate) serverRunning.getRestTemplate()).setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // pass through
            }
        });
    }

    @BeforeOAuth2Context
    @OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
    public void setUpUserAccounts() {
        RestOperations client = serverRunning.getRestTemplate();

        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName(JOE);
        user.setName(new ScimUser.Name("Joe", "User"));
        user.addEmail("joe@blah.com");
        user.setVerified(true);

        userForLoginServer = new ScimUser();
        userForLoginServer.setPassword("password");
        userForLoginServer.setUserName(loginServerJoe);
        userForLoginServer.setName(new ScimUser.Name("Joe_login_server", "User"));
        userForLoginServer.addEmail("joe_ls@blah.com");
        userForLoginServer.setVerified(true);
        userForLoginServer.setOrigin(LOGIN_SERVER);

        String userEndpoint = "/Users";
        ResponseEntity<ScimUser> newuser = client.postForEntity(serverRunning.getUrl(userEndpoint), user, ScimUser.class);
        userForLoginServer = client.postForEntity(serverRunning.getUrl(userEndpoint), userForLoginServer,
                ScimUser.class).getBody();

        joe = newuser.getBody();
        assertThat(joe.getUserName()).isEqualTo(JOE);

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("Passwo3d");

        headers.clear();
        ResponseEntity<Void> result = client
                .exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                        HttpMethod.PUT, new HttpEntity<>(change, headers),
                        Void.class, joe.getId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

        // The implicit grant for cf requires extra parameters in the
        // authorization request
        context.setParameters(Map.of("credentials",
                testAccounts.getJsonCredentials(joe.getUserName(), "Passwo3d")));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void authenticateReturnsUserID() {
        params.set("username", JOE);
        params.set("password", "Passwo3d");
        ResponseEntity<Map> response = serverRunning.postForMap("/authenticate", params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody())
                .containsEntry("username", JOE)
                .containsEntry(OriginKeys.ORIGIN, OriginKeys.UAA);
        assertThat(StringUtils.hasText((String) response.getBody().get("user_id"))).isTrue();
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void authenticateMarissaReturnsUserID() {
        params.set("username", testAccounts.getUserName());
        params.set("password", testAccounts.getPassword());
        ResponseEntity<Map> response = serverRunning.postForMap("/authenticate", params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("username", "marissa")
                .containsEntry(OriginKeys.ORIGIN, OriginKeys.UAA);
        assertThat((String) response.getBody().get("user_id")).isNotEmpty();
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void authenticateMarissaFails() {
        params.set("username", testAccounts.getUserName());
        params.set("password", "");
        ResponseEntity<Map> response = serverRunning.postForMap("/authenticate", params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void authenticateDoesNotReturnUserID() {
        params.set("username", testAccounts.getUserName());
        params.set("password", testAccounts.getPassword());
        ResponseEntity<Map> response = serverRunning.postForMap("/authenticate", params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("username", "marissa")
                .doesNotContainKey(OriginKeys.ORIGIN)
                .doesNotContainKey("user_id");
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void loginServerCanAuthenticateUserForCf() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        params.set("client_id", resource.getClientId());
        params.set("username", userForLoginServer.getUserName());
        params.set(OriginKeys.ORIGIN, userForLoginServer.getOrigin());
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String results = response.getHeaders().getLocation().toString();
        assertThat(results).as("There should be an access token: " + results).contains("access_token");
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void loginServerCanAuthenticateUserForAuthorizationCode() {
        params.set("client_id", testAccounts.getDefaultAuthorizationCodeResource().getClientId());
        params.set("response_type", "code");
        params.set("username", userForLoginServer.getUserName());
        params.set(OriginKeys.ORIGIN, userForLoginServer.getOrigin());
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        if (response.getStatusCode().is4xxClientError()) {
            fail(response.getBody().toString());
        } else {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            @SuppressWarnings("unchecked")
            Map<String, Object> results = response.getBody();
            // The approval page messaging response
            assertThat(results).as("There should be scopes: " + results).containsKey("scopes");
        }
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void loginServerCanAuthenticateUserWithIDForAuthorizationCode() {
        params.set("client_id", testAccounts.getDefaultAuthorizationCodeResource().getClientId());
        params.set("response_type", "code");
        params.set("user_id", userForLoginServer.getId());
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        if (response.getStatusCode().is4xxClientError()) {
            fail(response.getBody().toString());
        } else {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            @SuppressWarnings("unchecked")
            Map<String, Object> results = response.getBody();
            // The approval page messaging response
            assertThat(results).as("There should be scopes: " + results).containsKey("scopes");
        }
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void missingUserInfoIsError() {
        params.set("client_id", testAccounts.getDefaultImplicitResource().getClientId());
        params.remove("username");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        @SuppressWarnings("unchecked")
        Map<String, String> results = response.getBody();
        assertThat(results).as("There should be an error: " + results).containsKey("error");
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void missingUsernameIsError() {
        ((RestTemplate) serverRunning.getRestTemplate())
                .setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        params.set("client_id", testAccounts.getDefaultImplicitResource().getClientId());
        params.remove("username");
        // Some of the user info is there but not enough to determine a username
        params.set("given_name", "Mabel");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        @SuppressWarnings("unchecked")
        Map<String, String> results = response.getBody();
        assertThat(results).as("There should be an error: " + results).containsKey("error");
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void wrongUsernameIsErrorAddNewEnabled() {

        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(HttpClientBuilder.create().disableRedirectHandling().build());
        ((RestTemplate) serverRunning.getRestTemplate()).setRequestFactory(requestFactory);
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();

        params.set("client_id", resource.getClientId());
        params.set("username", "bogus1");
        params.set(UaaAuthenticationDetails.ADD_NEW, "true");
        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        // add_new:true user accounts are automatically provisioned.
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String results = response.getHeaders().getLocation().getFragment();
        assertThat(results).as("There should be an access token: " + results).contains("access_token");
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void wrongUsernameIsErrorAddNewDisabled() {

        ((RestTemplate) serverRunning.getRestTemplate())
                .setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();

        params.set("client_id", resource.getClientId());
        params.set("username", "bogus2");
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        @SuppressWarnings("unchecked")
        Map<String, String> results = response.getBody();
        assertThat(results).as("There should be an error: " + results).containsKey("error");
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void addNewUserWithWrongEmailFormat() {
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(HttpClientBuilder.create().disableRedirectHandling().build());
        ((RestTemplate) serverRunning.getRestTemplate()).setRequestFactory(requestFactory);
        params.set("client_id", testAccounts.getDefaultImplicitResource().getClientId());
        params.set("source", "login");
        params.set("username", "newuser");
        params.remove("given_name");
        params.remove("family_name");
        params.set("email", "noAtSign");
        params.set(UaaAuthenticationDetails.ADD_NEW, "true");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertThat(response).isNotNull()
                .extracting(ResponseEntity::getStatusCode)
                .isNotEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
                .isEqualTo(HttpStatus.FOUND);
        @SuppressWarnings("unchecked")
        Map<String, String> results = response.getBody();
        if (results != null) {
            assertThat(results).as("There should not be an error: " + results).doesNotContainKey("error");
        }
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void loginServerCfPasswordToken() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        headers.clear();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        params.set("client_id", resource.getClientId());
        params.set("client_secret", "");
        params.set("source", "login");
        params.set("username", userForLoginServer.getUserName());
        params.set(OriginKeys.ORIGIN, userForLoginServer.getOrigin());
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        params.set("grant_type", "password");
        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAccessTokenUri(), params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map results = response.getBody();
        assertThat(results).as("There should be a token: " + results).containsKey("access_token")
                .as("There should be a refresh: " + results).containsKey("refresh_token");
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void loginServerWithoutBearerToken() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        headers.clear();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", getAuthorizationEncodedValue(resource.getClientId(), ""));
        params.set("client_id", resource.getClientId());
        params.set("client_secret", "");
        params.set("source", "login");
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        params.set("grant_type", "password");
        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAccessTokenUri(), params, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    void loginServerCfInvalidClientPasswordToken() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        headers.clear();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        params.set("client_id", resource.getClientId());
        params.set("client_secret", "bogus");
        params.set("source", "login");
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        params.set("grant_type", "password");

        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAccessTokenUri(), params, headers);
        HttpStatusCode statusCode = response.getStatusCode();
        assertThat(statusCode == HttpStatus.FORBIDDEN || statusCode == HttpStatus.UNAUTHORIZED).as("Status code should be 401 or 403.").isTrue();
    }

    private String getAuthorizationEncodedValue(String username, String password) {
        String auth = username + ":" + password;
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.US_ASCII));
        return "Basic " + new String(encodedAuth);
    }

    private static class LoginClient extends ClientCredentialsResourceDetails {
        @SuppressWarnings("unused")
        public LoginClient(Object target) {
            LoginServerSecurityIntegrationTests test = (LoginServerSecurityIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                    new String[]{"oauth.login"}, "login", "loginsecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }
}
