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
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.CoreMatchers.containsString;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class AuthorizationCodeGrantIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Test
    public void testSuccessfulAuthorizationCodeFlow() throws Exception {
        testSuccessfulAuthorizationCodeFlow_Internal();
        testSuccessfulAuthorizationCodeFlow_Internal();
    }

    @Test
    public void testSuccessfulAuthorizationCodeFlowWithPkceS256() throws Exception {
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE, 
        		UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE, 
        		UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
    }
    
    @Test
    public void testSuccessfulAuthorizationCodeFlowWithPkcePlain() throws Exception {
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_CHALLENGE);
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_CHALLENGE);
    }
    
    @Test
    public void testPkcePlainWithWrongCodeVerifier() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_VERIFIER);
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String,String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_grant"));
        assertThat(body.get("error_description"), containsString("Invalid code verifier"));
    }
    
    @Test
    public void testPkceS256WithWrongCodeVerifier() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_CHALLENGE);
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String,String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_grant"));
        assertThat(body.get("error_description"), containsString("Invalid code verifier"));
    }
    
    @Test
    public void testMissingCodeChallenge() throws Exception {
    	ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest("", UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String,String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_grant"));
        assertThat(body.get("error_description"), containsString("PKCE error: Code verifier not required for this authorization code."));
    }
    
    @Test
    public void testMissingCodeVerifier() throws Exception {
    	ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, "");
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String,String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_grant"));
        assertThat(body.get("error_description"), containsString("PKCE error: Code verifier must be provided for this authorization code."));
    }
    
    @Test
    public void testInvalidCodeChallenge() throws Exception {
    	AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
    	String responseLocation = IntegrationTestUtils.getAuthorizationResponse(serverRunning,
        		resource.getClientId(),
        		testAccounts.getUserName(),
        		testAccounts.getPassword(),
        		resource.getPreEstablishedRedirectUri(),
        		"ShortCodeChallenge",
        		UaaTestAccounts.CODE_CHALLENGE_METHOD_S256); 
    	assertThat(responseLocation, containsString("Code challenge length must between 43 and 128 and use only [A-Z],[a-z],[0-9],_,.,-,~ characters."));
    }
    
    @Test
    public void testInvalidCodeVerifier() throws Exception {
    	AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
    	ResponseEntity<Map> tokenResponse = IntegrationTestUtils.getTokens(serverRunning,
        		testAccounts, 
        		resource.getClientId(), 
        		resource.getClientSecret(), 
        		resource.getPreEstablishedRedirectUri(), 
        		"invalidCodeVerifier",
        		"authorizationCode");
    	assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
    	Map<String,String> body = tokenResponse.getBody();
    	assertThat(body.get("error"), containsString("invalid_request"));
        assertThat(body.get("error_description"), containsString("Code verifier length must"));
    }
    
    @Test
    public void testUnsupportedCodeChallengeMethod() throws Exception {
    	AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
    	String responseLocation = IntegrationTestUtils.getAuthorizationResponse(serverRunning,
        		resource.getClientId(),
        		testAccounts.getUserName(),
        		testAccounts.getPassword(),
        		resource.getPreEstablishedRedirectUri(),
        		UaaTestAccounts.CODE_CHALLENGE,
        		"UnsupportedCodeChallengeMethod"); 
    	assertThat(responseLocation, containsString("Unsupported code challenge method."));
    }
    
	@Test
    public void testZoneDoesNotExist() {
        ServerRunning.UriBuilder builder = serverRunning.buildUri(serverRunning.getAuthorizationUri().replace("localhost", "testzonedoesnotexist.localhost"))
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
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    public void testZoneInactive() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");
        ServerRunning.UriBuilder builder = serverRunning.buildUri(serverRunning.getAuthorizationUri().replace("localhost", "testzoneinactive.localhost"))
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
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    public void testSuccessfulAuthorizationCodeFlow_Internal() {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

        Map<String, String> body = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                                                                                     testAccounts,
                                                                                     resource.getClientId(),
                                                                                     resource.getClientSecret(),
                                                                                     testAccounts.getUserName(),
                                                                                     testAccounts.getPassword());
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"aud\""));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"user_id\""));
    }
    
    private void testAuthorizationCodeFlowWithPkce_Internal(String codeChallenge, String codeChallengeMethod, String codeVerifier) throws Exception {
        
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(codeChallenge, codeChallengeMethod, codeVerifier);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        Map<String,String> body = tokenResponse.getBody();
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"aud\""));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"user_id\""));
        IntegrationTestUtils.callCheckToken(serverRunning,
        		testAccounts, 
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
        		testAccounts, 
        		resource.getClientId(), 
        		resource.getClientSecret(), 
        		resource.getPreEstablishedRedirectUri(), 
        		codeVerifier,
        		authorizationCode);
	}
}
