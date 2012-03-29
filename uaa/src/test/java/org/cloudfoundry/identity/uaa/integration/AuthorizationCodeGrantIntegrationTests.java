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

import java.net.URI;
import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

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

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "code")
				.queryParam("state", "mystateid").queryParam("client_id", "app")
				.queryParam("redirect_uri", "http://anywhere").build();
		ResponseEntity<Void> result = serverRunning.getForResponse(uri.toString(), headers);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		String location = result.getHeaders().getLocation().toString();

		if (result.getHeaders().containsKey("Set-Cookie")) {
			String cookie = result.getHeaders().getFirst("Set-Cookie");
			headers.set("Cookie", cookie);
		}

		ResponseEntity<String> response = serverRunning.getForString(location, headers);
		// should be directed to the login screen...
		assertTrue(response.getBody().contains("/login.do"));
		assertTrue(response.getBody().contains("username"));
		assertTrue(response.getBody().contains("password"));

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("username", testAccounts.getUserName());
		formData.add("password", testAccounts.getPassword());

		// Should be redirected to the original URL, but now authenticated
		result = serverRunning.postForResponse("/login.do", headers, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());

		if (result.getHeaders().containsKey("Set-Cookie")) {
			String cookie = result.getHeaders().getFirst("Set-Cookie");
			headers.set("Cookie", cookie);
		}

		response = serverRunning.getForString(result.getHeaders().getLocation().toString(), headers);
		// The grant access page should be returned
		assertTrue(response.getBody().contains("Do you authorize"));

		formData.clear();
		formData.add("user_oauth_approval", "true");
		result = serverRunning.postForResponse("/oauth/authorize", headers, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();
		assertTrue(location.matches("http://anywhere.*code=.+"));
	}

}
