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

import java.net.URI;
import java.util.Arrays;

import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Tests implicit grant using a direct posting of credentials to the /authorize endpoint and also with an intermediate
 * form login.
 * 
 * @author Dave Syer
 */
public class ImplicitTokenGrantIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

	@Rule
	public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);
	
	private String implicitUrl() {
		URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "token")
				.queryParam("client_id", "vmc").queryParam("redirect_uri", "https://uaa.cloudfoundry.com/redirect/vmc")
				.queryParam("scope", "cloud_controller.read").build();
		return uri.toString();
	}

	@Test
	public void authzViaJsonEndpointFailsWithHttpGet() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		String credentials = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", testAccounts.getUserName(),
				testAccounts.getPassword());

		ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl() + "&credentials={credentials}",
				headers, credentials);

		assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());

	}

	@Test
	public void authzViaJsonEndpointSucceedsWithCorrectCredentials() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", testAccounts.getUserName(),
				testAccounts.getPassword());

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("credentials", credentials);
		ResponseEntity<Void> result = serverRunning.postForResponse(implicitUrl(), headers, formData);

		assertNotNull(result.getHeaders().getLocation());
		assertTrue(result.getHeaders().getLocation().toString()
				.matches("https://uaa.cloudfoundry.com/redirect/vmc#access_token=.+"));

	}

	@Test
	public void authzViaJsonEndpointSucceedsWithAcceptForm() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_FORM_URLENCODED));

		String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", testAccounts.getUserName(),
				testAccounts.getPassword());

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("credentials", credentials);
		ResponseEntity<Void> result = serverRunning.postForResponse(implicitUrl(), headers, formData);

		URI location = result.getHeaders().getLocation();
		assertNotNull(location);
		assertTrue("Wrong location: " + location, location.toString()
				.matches("https://uaa.cloudfoundry.com/redirect/vmc#access_token=.+"));

	}

	@Test
	public void authzWithIntermediateFormLoginSucceeds() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl(), headers);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		String location = result.getHeaders().getLocation().toString();
		String cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		headers.set("Cookie", cookie);

		ResponseEntity<String> response = serverRunning.getForString(location, headers);
		// should be directed to the login screen...
		assertTrue(response.getBody().contains("/login.do"));
		assertTrue(response.getBody().contains("username"));
		assertTrue(response.getBody().contains("password"));

		location = "/login.do";

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("username", testAccounts.getUserName());
		formData.add("password", testAccounts.getPassword());

		result = serverRunning.postForRedirect(location, headers, formData);

		// System.err.println(result.getStatusCode());
		// System.err.println(result.getHeaders());

		assertNotNull(result.getHeaders().getLocation());
		assertTrue(result.getHeaders().getLocation().toString()
				.matches("https://uaa.cloudfoundry.com/redirect/vmc#access_token=.+"));
	}

}
