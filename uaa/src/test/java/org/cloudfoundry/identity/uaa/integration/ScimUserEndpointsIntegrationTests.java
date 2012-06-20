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

import java.util.Map;

import org.cloudfoundry.identity.uaa.scim.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.web.client.RestOperations;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class ScimUserEndpointsIntegrationTests {

	private final String JOEL = "joel_" + new RandomValueStringGenerator().generate().toLowerCase();

	private final String JOE = "joe_" + new RandomValueStringGenerator().generate().toLowerCase();

	private final String DELETE_ME = "deleteme_" + new RandomValueStringGenerator().generate().toLowerCase();

	private final String userEndpoint = "/User";

	private final String usersEndpoint = "/Users";

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);
	
	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

	@Rule
	public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);
	
	private RestOperations client;

	@Before
	public void createRestTemplate() throws Exception {

		Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));

		client = serverRunning.getRestTemplate();

	}

	@SuppressWarnings("rawtypes")
	private ResponseEntity<Map> deleteUser(String id, int version) {
		HttpHeaders headers = new HttpHeaders();
		headers.add("If-Match", "\"" + version + "\"");
		return client.exchange(serverRunning.getUrl(userEndpoint + "/{id}"), HttpMethod.DELETE, new HttpEntity<Void>(
				headers), Map.class, id);
	}

	private ResponseEntity<ScimUser> createUser(String username, String firstName, String lastName, String email) {
		ScimUser user = new ScimUser();
		user.setUserName(username);
		user.setName(new ScimUser.Name(firstName, lastName));
		user.addEmail(email);

		return client.postForEntity(serverRunning.getUrl(userEndpoint), user, ScimUser.class);
	}

	// curl -v -H "Content-Type: application/json" -H "Accept: application/json" --data
	// "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}" http://localhost:8080/uaa/User
	@Test
	public void createUserSucceeds() throws Exception {
		ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
		ScimUser joe1 = response.getBody();
		assertEquals(JOE, joe1.getUserName());

		// Check we can GET the user
		ScimUser joe2 = client
				.getForObject(serverRunning.getUrl(userEndpoint + "/{id}"), ScimUser.class, joe1.getId());

		assertEquals(joe1.getId(), joe2.getId());
	}

	@Test
	public void createUserWithNoEmailFails() throws Exception {
		ScimUser user = new ScimUser();
		user.setUserName("dave");
		user.setName(new ScimUser.Name("Dave", "Syer"));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = client.postForEntity(serverRunning.getUrl(userEndpoint), user, Map.class);
		@SuppressWarnings("unchecked")
		Map<String, String> error = response.getBody();

		System.err.println(error);
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
		assertEquals("invalid_user", error.get("error"));

	}

	@Test
	public void getUserHasEtag() throws Exception {
		ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
		ScimUser joe = response.getBody();
		assertEquals(JOE, joe.getUserName());

		// Check we can GET the user
		ResponseEntity<ScimUser> result = client.getForEntity(serverRunning.getUrl(userEndpoint + "/{id}"),
				ScimUser.class, joe.getId());
		assertEquals("\"" + joe.getVersion() + "\"", result.getHeaders().getFirst("ETag"));
	}

	// curl -v -H "Content-Type: application/json" -X PUT -H "Accept: application/json" --data
	// "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}" http://localhost:8080/uaa/User
	@Test
	public void updateUserSucceeds() throws Exception {
		ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
		ScimUser joe = response.getBody();
		assertEquals(JOE, joe.getUserName());

		joe.setName(new ScimUser.Name("Joe", "Bloggs"));

		HttpHeaders headers = new HttpHeaders();
		headers.add("If-Match", "\"" + joe.getVersion() + "\"");
		response = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}", HttpMethod.PUT,
				new HttpEntity<ScimUser>(joe, headers), ScimUser.class, joe.getId());
		ScimUser joe1 = response.getBody();
		assertEquals(JOE, joe1.getUserName());

		assertEquals(joe.getId(), joe1.getId());

	}

	@Test
	public void updateUserWithNewAuthoritiesSucceeds() throws Exception {
		ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
		ScimUser joe = response.getBody();
		assertEquals(JOE, joe.getUserName());

		joe.setUserType("admin");

		HttpHeaders headers = new HttpHeaders();
		headers.add("If-Match", "\"" + joe.getVersion() + "\"");
		response = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}", HttpMethod.PUT,
				new HttpEntity<ScimUser>(joe, headers), ScimUser.class, joe.getId());
		ScimUser joe1 = response.getBody();
		assertEquals(JOE, joe1.getUserName());

		assertEquals(joe.getId(), joe1.getId());

	}

	// curl -v -H "Content-Type: application/json" -X PUT -H "Accept: application/json" --data
	// "{\"password\":\"newpassword\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}"
	// http://localhost:8080/uaa/User/{id}/password
	@Test
	public void changePasswordSucceeds() throws Exception {
		ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
		ScimUser joe = response.getBody();
		assertEquals(JOE, joe.getUserName());

		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<Void> result = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
				HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers), null, joe.getId());
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());

	}

	// curl -v -H "Content-Type: application/json" -H "Accept: application/json" -H 'If-Match: "0"' --data
	// "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}" http://localhost:8080/uaa/User
	@Test
	public void createUserTwiceFails() throws Exception {
		ScimUser user = new ScimUser();
		user.setUserName(JOEL);
		user.setName(new ScimUser.Name("Joel", "D'sa"));
		user.addEmail("joel@blah.com");

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = client.postForEntity(serverRunning.getUrl(userEndpoint), user, Map.class);
		@SuppressWarnings("unchecked")
		Map<String, String> joel = response.getBody();
		assertEquals(JOEL, joel.get("userName"));

		response = client.postForEntity(serverRunning.getUrl(userEndpoint), user, Map.class);
		@SuppressWarnings("unchecked")
		Map<String, String> error = response.getBody();

		// System.err.println(error);
		assertEquals("user_already_exists", error.get("error"));

	}

	// curl -v -H "Content-Type: application/json" -H "Accept: application/json" -X DELETE
	// -H "If-Match: 0" http://localhost:8080/uaa/User/joel
	@Test
	public void deleteUserWithWrongIdFails() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = deleteUser("9999", 0);
		@SuppressWarnings("unchecked")
		Map<String, String> error = response.getBody();
		// System.err.println(error);
		assertEquals("user_not_found", error.get("error"));
		assertEquals("User 9999 does not exist", error.get("message"));

	}

	// curl -v -H "Content-Type: application/json" -H "Accept: application/json" -X DELETE
	// http://localhost:8080/uaa/User/joel
	@Test
	public void deleteUserWithNoEtagSucceeds() throws Exception {
		ScimUser deleteMe = createUser(DELETE_ME, "Delete", "Me", "deleteme@blah.com").getBody();

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = client.exchange(serverRunning.getUrl(userEndpoint + "/{id}"),
				HttpMethod.DELETE, new HttpEntity<Void>((Void) null), Map.class, deleteMe.getId());
		assertEquals(HttpStatus.OK, response.getStatusCode());
	}

	@Test
	public void getReturnsNotFoundForNonExistentUser() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = client.exchange(serverRunning.getUrl(userEndpoint + "/{id}"),
				HttpMethod.GET, new HttpEntity<Void>((Void) null), Map.class, "9999");
		@SuppressWarnings("unchecked")
		Map<String, String> error = response.getBody();
		assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
		assertEquals("user_not_found", error.get("error"));
		assertEquals("User 9999 does not exist", error.get("message"));
	}

	@Test
	public void findUsers() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint, Map.class);
		@SuppressWarnings("unchecked")
		Map<String, Object> results = response.getBody();
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertTrue("There should be more than zero users", (Integer) results.get("totalResults") > 0);
	}

	@Test
	public void findUsersWithAttributes() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint + "?attributes=id,userName", Map.class);
		@SuppressWarnings("unchecked")
		Map<String, Object> results = response.getBody();
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertTrue("There should be more than zero users", (Integer) results.get("totalResults") > 0);
	}

	@Test
	public void findUsersWithSortBy() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint + "?sortBy=emails.value", Map.class);
		@SuppressWarnings("unchecked")
		Map<String, Object> results = response.getBody();
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertTrue("There should be more than zero users", (Integer) results.get("totalResults") > 0);
	}

}
