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

import java.util.Arrays;
import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class CheckTokenEndpointIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

	@Rule
	public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

	@Test
	public void testDecodeToken() throws Exception {

		{
			MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
			formData.add("grant_type", "password");
			formData.add("username", testAccounts.getUserName());
			formData.add("password", testAccounts.getPassword());
			formData.add("scope", "cloud_controller.read");

			HttpHeaders headers = new HttpHeaders();
			ResourceOwnerPasswordResourceDetails app = testAccounts.getDefaultResourceOwnerPasswordResource();
			headers.set("Authorization", testAccounts.getAuthorizationHeader(app.getClientId(), app.getClientSecret()));
			headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

			//Get an access token to add an approval
			@SuppressWarnings("rawtypes")
			ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
			assertEquals(HttpStatus.OK, response.getStatusCode());
			String token = (String) response.getBody().get("access_token");

			// add an approval for the scope requested
			HttpHeaders approvalHeaders = new HttpHeaders();
			approvalHeaders.set("Authorization", "bearer " + token);
			ResponseEntity<Approval[]> approvals = serverRunning.getRestTemplate().exchange(
					serverRunning.getUrl("/approvals"),
					HttpMethod.PUT,
					new HttpEntity<Approval[]>((new Approval[]{new Approval(testAccounts.getUserName(), "app",
							"cloud_controller.read", 50000, ApprovalStatus.APPROVED)}), approvalHeaders), Approval[].class);

			assertEquals(HttpStatus.OK, approvals.getStatusCode());
		}

		// Get a fresh access token
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("username", testAccounts.getUserName());
		formData.add("password", testAccounts.getPassword());
		formData.add("scope", "cloud_controller.read");

		HttpHeaders headers = new HttpHeaders();
		ResourceOwnerPasswordResourceDetails app = testAccounts.getDefaultResourceOwnerPasswordResource();
		headers.set("Authorization", testAccounts.getAuthorizationHeader(app.getClientId(), app.getClientSecret()));
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		//Get an access token to add an approval
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		String token = (String) response.getBody().get("access_token");

		formData = new LinkedMultiValueMap<String, String>();
		ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
		headers.set("Authorization", testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
		formData.add("token", token);

		response = serverRunning.postForMap("/check_token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		System.err.println(response.getBody());

		@SuppressWarnings("unchecked")
		Map<String, String> map = response.getBody();
		assertEquals(testAccounts.getUserName(), map.get("user_name"));
		assertEquals(testAccounts.getEmail(), map.get("email"));

	}

	@Test
	public void testTokenKey() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
		headers.set("Authorization", testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.getForObject("/token_key", Map.class, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String, String> map = response.getBody();
		// System.err.println(map);
		assertNotNull(map.get("alg"));
		assertNotNull(map.get("value"));

	}

	@Test
	public void testUnauthorized() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("token", "FOO");
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/check_token", formData, headers);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

		@SuppressWarnings("unchecked")
		Map<String, String> map = response.getBody();
		assertTrue(map.containsKey("error"));

	}

	@Test
	public void testForbidden() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("token", "FOO");
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", "Basic " + new String(Base64.encode("vmc:".getBytes("UTF-8"))));
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/check_token", formData, headers);
		assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

		@SuppressWarnings("unchecked")
		Map<String, String> map = response.getBody();
		assertTrue(map.containsKey("error"));

	}

}
