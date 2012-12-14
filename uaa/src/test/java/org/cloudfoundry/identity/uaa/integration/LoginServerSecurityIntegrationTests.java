/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.Map;

import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * Integration test to verify that the Login Server authentication channel is open and working.
 * 
 * @author Dave Syer
 */
public class LoginServerSecurityIntegrationTests {

	private final String JOE = "joe" + new RandomValueStringGenerator().generate().toLowerCase();

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

	@Before
	public void init() {
		params.set("source", "login");
		params.set("redirect_uri", "http://none");
		params.set("response_type", "token");
		params.set("username", joe.getUserName());
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
	}

	@BeforeOAuth2Context
	@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
	public void setUpUserAccounts() {

		// If running against vcap we don't want to run these tests because they create new user accounts
		Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));

		RestOperations client = serverRunning.getRestTemplate();

		ScimUser user = new ScimUser();
		user.setUserName(JOE);
		user.setName(new ScimUser.Name("Joe", "User"));
		user.addEmail("joe@blah.com");

		ResponseEntity<ScimUser> newuser = client.postForEntity(serverRunning.getUrl(userEndpoint), user,
				ScimUser.class);

		joe = newuser.getBody();
		assertEquals(JOE, joe.getUserName());

		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("password");

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<Void> result = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
				HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers), null, joe.getId());
		assertEquals(HttpStatus.OK, result.getStatusCode());

		// The implicit grant for vmc requires extra parameters in the authorization request
		context.setParameters(Collections.singletonMap("credentials",
				testAccounts.getJsonCredentials(joe.getUserName(), "password")));

	}

	@Test
	@OAuth2ContextConfiguration(LoginClient.class)
	public void testLoginServerCanAuthenticateUserForVmc() throws Exception {
		ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
		params.set("client_id", resource.getClientId());
		String redirect = resource.getPreEstablishedRedirectUri();
		if (redirect != null) {
			params.set("redirect_uri", redirect);
		}
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
		assertEquals(HttpStatus.FOUND, response.getStatusCode());
		String results = response.getHeaders().getLocation().toString();
		assertNotNull("There should be scopes: " + results, results.contains("#access_token"));
	}

	@Test
	@OAuth2ContextConfiguration(LoginClient.class)
	public void testLoginServerCanAuthenticateUserForAuthorizationCode() throws Exception {
		params.set("client_id", testAccounts.getDefaultAuthorizationCodeResource().getClientId());
		params.set("response_type", "code");
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
	public void testMissingUserInfoIsError() throws Exception {
		params.set("client_id", testAccounts.getDefaultImplicitResource().getClientId());
		params.remove("username");
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
		// TODO: should be 302
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String, String> results = response.getBody();
		assertNotNull("There should be an error: " + results, results.containsKey("error"));
	}

	@Test
	@OAuth2ContextConfiguration(LoginClient.class)
	public void testMissingUsernameIsError() throws Exception {
		((RestTemplate) serverRunning.getRestTemplate())
				.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
		params.set("client_id", testAccounts.getDefaultImplicitResource().getClientId());
		params.remove("username");
		// Some of the user info is there but not enough to determine a username
		params.set("given_name", "Mabel");
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
		// TODO: should be 302
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String, String> results = response.getBody();
		assertNotNull("There should be an error: " + results, results.containsKey("error"));
	}

	@Test
	@OAuth2ContextConfiguration(LoginClient.class)
	public void testWrongUsernameIsError() throws Exception {
		((RestTemplate) serverRunning.getRestTemplate())
				.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
		ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
		params.set("client_id", resource.getClientId());
		params.set("username", "bogus");
		String redirect = resource.getPreEstablishedRedirectUri();
		if (redirect != null) {
			params.set("redirect_uri", redirect);
		}
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap(serverRunning.getAuthorizationUri(), params, headers);
		if (testAccounts.isProfileActive("default")) {
			// In the default profile user accounts are automatically provisioned
			assertEquals(HttpStatus.FOUND, response.getStatusCode());
			String results = response.getHeaders().getLocation().getFragment();
			assertTrue("There should be an access token: " + results, results.contains("access_token"));
		} else { // user account is not automatically provisioned
			assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
			@SuppressWarnings("unchecked")
			Map<String,String> results = response.getBody();
			assertNotNull("There should be an error: " + results, results.containsKey("error"));			
		}
	}

	private static class LoginClient extends ClientCredentialsResourceDetails {
		@SuppressWarnings("unused")
		public LoginClient(Object target) {
			LoginServerSecurityIntegrationTests test = (LoginServerSecurityIntegrationTests) target;
			ClientCredentialsResourceDetails resource = test.testAccounts.getClientCredentialsResource(
					"oauth.clients.login", "login", "loginsecret");
			setClientId(resource.getClientId());
			setClientSecret(resource.getClientSecret());
			setId(getClientId());
			setAccessTokenUri(test.serverRunning.getAccessTokenUri());
		}
	}

}
