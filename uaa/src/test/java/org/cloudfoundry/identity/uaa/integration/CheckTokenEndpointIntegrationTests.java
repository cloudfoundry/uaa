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

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
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
	
	/**
	 * tests a happy-day flow of the <code>/check_token</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {
		
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("username", testAccounts.getUserName());
		formData.add("password", testAccounts.getPassword());
		formData.add("scope", "read");

		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes("UTF-8"))));
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		String token = (String) response.getBody().get("access_token");

		formData = new LinkedMultiValueMap<String, String>();
		formData.add("token", token);

		response = serverRunning.postForMap("/check_token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		System.err.println(response.getBody());

		@SuppressWarnings("unchecked")
		Map<String, String> map = response.getBody();
		assertEquals(testAccounts.getUserName(), map.get("user_id"));
		assertEquals(testAccounts.getEmail(), map.get("email"));

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
