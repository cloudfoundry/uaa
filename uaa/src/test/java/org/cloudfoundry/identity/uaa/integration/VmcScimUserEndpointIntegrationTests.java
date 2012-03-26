/**
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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.scim.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * Integration test to verify that the trusted client use cases are supported adequately for vmc.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.GrantType.IMPLICIT)
public class VmcScimUserEndpointIntegrationTests {

	private final String JOE = "joe" + new RandomValueStringGenerator().generate().toLowerCase();

	private final String userEndpoint = "/User";

	private final String usersEndpoint = "/Users";

	private ScimUser joe;

	@Rule
	public ServerRunning server = ServerRunning.isRunning();
	
	private TestAccounts testAccounts = TestAccounts.standard(server);	

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(server, testAccounts);

	@BeforeOAuth2Context
	public void setUpUserAccounts() {

		// If running against vcap we don't want to run these tests because they create new user accounts
		Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));		

		RestTemplate client = context.getRestTemplate();

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = server.getForObject(usersEndpoint + "?filter=userName eq 'joe'", Map.class);
		@SuppressWarnings("unchecked")
		List<Map<String, String>> results = (List<Map<String, String>>) response.getBody().get("resources");
		// System.err.println(results);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		for (Map<String, String> map : results) {
			String id = map.get("id");
			deleteUser(client, id); // ignore errors
		}

		ScimUser user = new ScimUser();
		user.setUserName(JOE);
		user.setName(new ScimUser.Name("Joe", "User"));
		user.addEmail("joe@blah.com");

		ResponseEntity<ScimUser> newuser = client.postForEntity(server.getUrl(userEndpoint), user, ScimUser.class);

		joe = newuser.getBody();
		assertEquals(JOE, joe.getUserName());

		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("password");

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<Void> result = client.exchange(server.getUrl(userEndpoint) + "/{id}/password", HttpMethod.PUT,
				new HttpEntity<PasswordChangeRequest>(change, headers), null, joe.getId());
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());

		context.setParameters(Collections.singletonMap("credentials", testAccounts.getJsonCredentials(joe.getUserName(), "password")));

	}

	@SuppressWarnings("rawtypes")
	private ResponseEntity<Map> deleteUser(RestOperations client, String id) {
		HttpHeaders headers = new HttpHeaders();
		headers.add("If-Match", "*");
		return client.exchange(server.getUrl(userEndpoint + "/{id}"), HttpMethod.DELETE, new HttpEntity<Void>(headers),
				Map.class, id);
	}

	@SuppressWarnings("rawtypes")
	private ResponseEntity<Map> deleteUser(RestOperations client, String id, int version) {
		HttpHeaders headers = new HttpHeaders();
		headers.add("If-Match", "\"" + version + "\"");
		return client.exchange(server.getUrl(userEndpoint + "/{id}"), HttpMethod.DELETE, new HttpEntity<Void>(headers),
				Map.class, id);
	}

	@Test
	public void changePasswordSucceeds() throws Exception {

		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setOldPassword("password");
		change.setPassword("newpassword");

		HttpHeaders headers = new HttpHeaders();
		RestTemplate client = server.getRestTemplate();
		ResponseEntity<Void> result = client.exchange(server.getUrl(userEndpoint) + "/{id}/password", HttpMethod.PUT,
				new HttpEntity<PasswordChangeRequest>(change, headers), null, joe.getId());
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());

	}

	@Test
	public void deleteUserFails() throws Exception {
		RestTemplate client = server.getRestTemplate();
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = deleteUser(client, joe.getId(), joe.getVersion());
		// It's unauthorized because the resource ids mismatch - arguably it should be FORBIDDEN
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String, String> error = response.getBody();
		// System.err.println(error);
		assertEquals("invalid_token", error.get("error"));
	}

	@Test
	public void findUsersFails() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = server.getForObject(usersEndpoint, Map.class);
		@SuppressWarnings("unchecked")
		Map<String, Object> results = response.getBody();
		// It's unauthorized because the resource ids mismatch - arguably it should be FORBIDDEN
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
		assertNotNull("There should be an error", results.get("error"));
	}

}
