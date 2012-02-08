/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;
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
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * Integration test to verify that the trusted client use cases are supported adequately for vmc.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class VmcScimUserEndpointIntegrationTests {

	private final String userEndpoint = "/User";

	private final String usersEndpoint = "/Users";

	private ScimUser joe;

	@Rule
	public ServerRunning server = ServerRunning.isRunning();

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.implicit(server, "joe", "password");

	@Rule
	public TestAccountSetup testAccounts = TestAccountSetup.withLegacyTokenServerForProfile("mocklegacy");
	
	@Before
	public void checkLegacy() {
		Assume.assumeTrue(!testAccounts.isLegacy());		
	}
	
	@BeforeOAuth2Context
	public void setUpUserAccounts() {

		if (testAccounts.isLegacy()) {
			// Don't try to set up test account if we are in legacy mode
			return;		
		}

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
		user.setUserName("joe");
		user.setName(new ScimUser.Name("Joe", "User"));
		user.addEmail("joe@blah.com");

		ResponseEntity<ScimUser> newuser = client.postForEntity(server.getUrl(userEndpoint), user, ScimUser.class);

		joe = newuser.getBody();
		assertEquals("joe", joe.getUserName());

		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("password");

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<Void> result = client.exchange(server.getUrl(userEndpoint) + "/{id}/password", HttpMethod.PUT,
				new HttpEntity<PasswordChangeRequest>(change, headers), null, joe.getId());
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());

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
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String, String> error = response.getBody();
		// System.err.println(error);
		assertEquals("Access is denied", error.get("error"));
	}

	@Test
	public void findUsersFails() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = server.getForObject(usersEndpoint, Map.class);
		@SuppressWarnings("unchecked")
		Map<String, Object> results = response.getBody();
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
		assertNotNull("There should be an error", results.get("error"));
	}

}
