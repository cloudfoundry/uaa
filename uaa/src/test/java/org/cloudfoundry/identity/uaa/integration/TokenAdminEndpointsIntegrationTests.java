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
import static org.junit.Assert.assertTrue;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 */
public class TokenAdminEndpointsIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

	@Rule
	public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

	@Before
	public void setUp() {
		Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));
	}

	@Test
	@OAuth2ContextConfiguration(resource = TokenResourceOwnerPassword.class)
	public void testListTokensByUser() throws Exception {

		ResponseEntity<String> result = serverRunning.getForString("/oauth/users/" + testAccounts.getUserName()
				+ "/tokens");
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().contains(context.getAccessToken().getValue()));
	}

	@Test
	@OAuth2ContextConfiguration(resource = TokenResourceOwnerPassword.class)
	public void testRevokeTokenByUser() throws Exception {

		OAuth2AccessToken token = context.getAccessToken();
		String hash = new StandardPasswordEncoder().encode(token.getValue());

		HttpEntity<?> request = new HttpEntity<String>(token.getValue());
		assertEquals(
				HttpStatus.NO_CONTENT,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/oauth/users/{user}/tokens/{token}"), HttpMethod.DELETE,
								request, Void.class, testAccounts.getUserName(), hash).getStatusCode());

		ResponseEntity<String> result = serverRunning.getForString("/oauth/users/" + testAccounts.getUserName()
				+ "/tokens");
		assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
		assertTrue(result.getBody().contains("invalid_token"));

	}

	@Test
	@OAuth2ContextConfiguration(resource = TokenResourceOwnerPassword.class)
	public void testRevokeBogusToken() throws Exception {

		HttpEntity<?> request = new HttpEntity<String>(context.getAccessToken().getValue());
		assertEquals(
				HttpStatus.NOT_FOUND,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/oauth/users/{user}/tokens/{token}"), HttpMethod.DELETE,
								request, Void.class, testAccounts.getUserName(), "FOO").getStatusCode());

	}

	@Test
	@OAuth2ContextConfiguration(resource = TokenResourceOwnerPassword.class)
	public void testClientListsTokensByUser() throws Exception {

		ResponseEntity<String> result = serverRunning.getForString("/oauth/users/" + testAccounts.getUserName()
				+ "/tokens");
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().startsWith("["));
		assertTrue(result.getBody().endsWith("]"));
		assertTrue(result.getBody().length() > 0);
	}

	@Test
	@OAuth2ContextConfiguration(resource = TokenResourceOwnerPassword.class)
	public void testCannotListTokensOfAnotherUser() throws Exception {

		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getForString("/oauth/users/foo/tokens").getStatusCode());
	}

	@Test
	@OAuth2ContextConfiguration(resource = OAuth2ContextConfiguration.ClientCredentials.class)
	public void testListTokensByClient() throws Exception {

		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/scim/tokens");
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().contains(context.getAccessToken().getValue()));
	}

	@Test
	@OAuth2ContextConfiguration(resource = OAuth2ContextConfiguration.ClientCredentials.class)
	public void testCannotListTokensOfAnotherClient() throws Exception {
		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getForString("/oauth/clients/token/tokens").getStatusCode());
	}

	@Test
	@OAuth2ContextConfiguration(resource = OAuth2ContextConfiguration.ClientCredentials.class)
	public void testRevokeTokenByClient() throws Exception {

		OAuth2AccessToken token = context.getAccessToken();
		String hash = new StandardPasswordEncoder().encode(token.getValue());

		HttpEntity<?> request = new HttpEntity<String>(token.getValue());
		assertEquals(
				HttpStatus.NO_CONTENT,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/oauth/clients/scim/tokens/" + hash), HttpMethod.DELETE,
								request, Void.class).getStatusCode());

		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/scim/tokens/");
		assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
		assertTrue(result.getBody().contains("invalid_token"));

	}

	@Test
	@OAuth2ContextConfiguration
	public void testUserCannotListTokensOfClient() throws Exception {
		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getForString("/oauth/clients/app/tokens").getStatusCode());
	}

	static class TokenResourceOwnerPassword extends ResourceOwnerPasswordResourceDetails {
		public TokenResourceOwnerPassword(TestAccounts testAccounts) {
			ResourceOwnerPasswordResourceDetails resource = ((UaaTestAccounts) testAccounts)
					.getResourceOwnerPasswordResource(new String[] { "read", "write" }, "oauth.clients.token", "token",
							"tokenclientsecret", testAccounts.getUserName(), testAccounts.getPassword());
			OAuth2ContextConfiguration.ResourceHelper.initialize(resource, this);
			setUsername(resource.getUsername());
			setPassword(resource.getPassword());
		}
	}

}
