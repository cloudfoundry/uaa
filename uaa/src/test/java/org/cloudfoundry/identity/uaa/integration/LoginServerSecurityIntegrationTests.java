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

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.account.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.Charset;
import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Integration test to verify that the Login Server authentication channel is
 * open and working.
 *
 * @author Dave Syer
 */
public class LoginServerSecurityIntegrationTests {

    private final String JOE = "joe" + new RandomValueStringGenerator().generate().toLowerCase();
    private final String LOGIN_SERVER_JOE = "ls_joe" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String userEndpoint = "/Users";

    private ScimUser joe;

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

    private HttpHeaders headers = new HttpHeaders();
    private ScimUser userForLoginServer;

    @Before
    public void init() {
        params.set("source", "login");
        params.set("redirect_uri", "http://localhost:8080/app/");
        params.set("response_type", "token");
        if (joe!=null) {
            params.set("username", joe.getUserName());
        }
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ((RestTemplate)serverRunning.getRestTemplate()).setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
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
        userForLoginServer.setUserName(LOGIN_SERVER_JOE);
        userForLoginServer.setName(new ScimUser.Name("Joe_login_server", "User"));
        userForLoginServer.addEmail("joe_ls@blah.com");
        userForLoginServer.setVerified(true);
        userForLoginServer.setOrigin(LOGIN_SERVER);

        ResponseEntity<ScimUser> newuser = client.postForEntity(serverRunning.getUrl(userEndpoint), user,
                        ScimUser.class);
        userForLoginServer = client.postForEntity(serverRunning.getUrl(userEndpoint), userForLoginServer,
                ScimUser.class).getBody();

        joe = newuser.getBody();
        assertEquals(JOE, joe.getUserName());

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("Passwo3d");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client
                        .exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                                        HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers),
                                        Void.class, joe.getId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

        // The implicit grant for cf requires extra parameters in the
        // authorization request
        context.setParameters(Collections.singletonMap("credentials",
                        testAccounts.getJsonCredentials(joe.getUserName(), "Passwo3d")));

    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testAuthenticateReturnsUserID() {
        params.set("username", JOE);
        params.set("password", "Passwo3d");
        ResponseEntity<Map> response = serverRunning.postForMap("/authenticate", params, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(JOE, response.getBody().get("username"));
        assertEquals(OriginKeys.UAA, response.getBody().get(OriginKeys.ORIGIN));
        assertTrue(StringUtils.hasText((String)response.getBody().get("user_id")));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testAuthenticateMarissaReturnsUserID() {
        params.set("username", testAccounts.getUserName());
        params.set("password", testAccounts.getPassword());
        ResponseEntity<Map> response = serverRunning.postForMap("/authenticate", params, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("marissa", response.getBody().get("username"));
        assertEquals(OriginKeys.UAA, response.getBody().get(OriginKeys.ORIGIN));
        assertTrue(StringUtils.hasText((String)response.getBody().get("user_id")));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testAuthenticateMarissaFails() {
        params.set("username", testAccounts.getUserName());
        params.set("password", "");
        ResponseEntity<Map> response = serverRunning.postForMap("/authenticate", params, headers);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    public void testAuthenticateDoesNotReturnsUserID() {
        params.set("username", testAccounts.getUserName());
        params.set("password", testAccounts.getPassword());
        ResponseEntity<Map> response = serverRunning.postForMap("/authenticate", params, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("marissa", response.getBody().get("username"));
        assertNull(response.getBody().get(OriginKeys.ORIGIN));
        assertNull(response.getBody().get("user_id"));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testLoginServerCanAuthenticateUserForCf() {
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
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        String results = response.getHeaders().getLocation().toString();
        assertTrue("There should be an access token: " + results, results.contains("access_token"));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testLoginServerCanAuthenticateUserForAuthorizationCode() {
        params.set("client_id", testAccounts.getDefaultAuthorizationCodeResource().getClientId());
        params.set("response_type", "code");
        params.set("username", userForLoginServer.getUserName());
        params.set(OriginKeys.ORIGIN, userForLoginServer.getOrigin());
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        // The approval page messaging response
        assertNotNull("There should be scopes: " + results, results.get("scopes"));
    }
    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testLoginServerCanAuthenticateUserWithIDForAuthorizationCode() {
        params.set("client_id", testAccounts.getDefaultAuthorizationCodeResource().getClientId());
        params.set("response_type", "code");
        params.set("user_id", userForLoginServer.getId());
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        // The approval page messaging response
        assertNotNull("There should be scopes: " + results, results.get("scopes"));
    }


    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testMissingUserInfoIsError() {
        params.set("client_id", testAccounts.getDefaultImplicitResource().getClientId());
        params.remove("username");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> results = response.getBody();
        assertTrue("There should be an error: " + results, results.containsKey("error"));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testMissingUsernameIsError() {
        ((RestTemplate) serverRunning.getRestTemplate())
                        .setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        params.set("client_id", testAccounts.getDefaultImplicitResource().getClientId());
        params.remove("username");
        // Some of the user info is there but not enough to determine a username
        params.set("given_name", "Mabel");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> results = response.getBody();
        assertTrue("There should be an error: " + results, results.containsKey("error"));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testWrongUsernameIsErrorAddNewEnabled() {

        ((RestTemplate) serverRunning.getRestTemplate())
                        .setRequestFactory(new HttpComponentsClientHttpRequestFactory());
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
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        String results = response.getHeaders().getLocation().getFragment();
        assertTrue("There should be an access token: " + results, results.contains("access_token"));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testWrongUsernameIsErrorAddNewDisabled() {

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
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> results = response.getBody();
        assertTrue("There should be an error: " + results, results.containsKey("error"));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testAddNewUserWithWrongEmailFormat() {
        ((RestTemplate) serverRunning.getRestTemplate())
                        .setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        params.set("client_id", testAccounts.getDefaultImplicitResource().getClientId());
        params.set("source","login");
        params.set("username", "newuser");
        params.remove("given_name");
        params.remove("family_name");
        params.set("email", "noAtSign");
        params.set(UaaAuthenticationDetails.ADD_NEW, "true");
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
        assertNotNull(response);
        assertNotEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> results = response.getBody();
        if (results != null) {
            assertFalse("There should not be an error: " + results, results.containsKey("error"));
        }
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testLoginServerCfPasswordToken() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept",MediaType.APPLICATION_JSON_VALUE);
        params.set("client_id", resource.getClientId());
        params.set("client_secret","");
        params.set("source","login");
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
        assertEquals(HttpStatus.OK, response.getStatusCode());
        Map results = response.getBody();
        assertTrue("There should be a token: " + results, results.containsKey("access_token"));
        assertTrue("There should be a refresh: " + results, results.containsKey("refresh_token"));
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testLoginServerWithoutBearerToken() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept",MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", getAuthorizationEncodedValue(resource.getClientId(), ""));
        params.set("client_id", resource.getClientId());
        params.set("client_secret","");
        params.set("source","login");
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        params.set("grant_type", "password");
        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAccessTokenUri(), params, headers);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    @OAuth2ContextConfiguration(LoginClient.class)
    public void testLoginServerCfInvalidClientPasswordToken() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept",MediaType.APPLICATION_JSON_VALUE);
        params.set("client_id", resource.getClientId());
        params.set("client_secret","bogus");
        params.set("source","login");
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        params.set("grant_type", "password");

        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAccessTokenUri(), params, headers);
        HttpStatus statusCode = response.getStatusCode();
        assertTrue("Status code should be 401 or 403.", statusCode==HttpStatus.FORBIDDEN || statusCode==HttpStatus.UNAUTHORIZED);
    }

    @Test
    @OAuth2ContextConfiguration(AppClient.class)
    public void testLoginServerCfInvalidClientToken() {
        ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Accept",MediaType.APPLICATION_JSON_VALUE);
        params.set("client_id", resource.getClientId());
        params.set("client_secret","bogus");
        params.set("source","login");
        params.set(UaaAuthenticationDetails.ADD_NEW, "false");
        params.set("grant_type", "password");

        String redirect = resource.getPreEstablishedRedirectUri();
        if (redirect != null) {
            params.set("redirect_uri", redirect);
        }
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAccessTokenUri(), params, headers);
        HttpStatus statusCode = response.getStatusCode();

        assertTrue("Status code should be 401 or 403.", statusCode==HttpStatus.FORBIDDEN || statusCode==HttpStatus.UNAUTHORIZED);
    }

    private String getAuthorizationEncodedValue(String username, String password) {
        String auth = username + ":" + password;
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("US-ASCII")));
        return "Basic " + new String( encodedAuth );
    }


    private static class LoginClient extends ClientCredentialsResourceDetails {
        @SuppressWarnings("unused")
        public LoginClient(Object target) {
            LoginServerSecurityIntegrationTests test = (LoginServerSecurityIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
                            new String[] {"oauth.login"}, "login", "loginsecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }

    private static class AppClient extends ClientCredentialsResourceDetails {
        @SuppressWarnings("unused")
        public AppClient(Object target) {
            LoginServerSecurityIntegrationTests test = (LoginServerSecurityIntegrationTests) target;
            ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource("app", "appclientsecret");
            setClientId(resource.getClientId());
            setClientSecret(resource.getClientSecret());
            setId(getClientId());
            setAccessTokenUri(test.serverRunning.getAccessTokenUri());
        }
    }

}
