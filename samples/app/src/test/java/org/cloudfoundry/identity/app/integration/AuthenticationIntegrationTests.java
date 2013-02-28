/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.app.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
public class AuthenticationIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

	@Rule
	public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

	@Test
	public void formLoginSucceeds() throws Exception {

		ResponseEntity<Void> result;
		String location;
		String cookie;

		HttpHeaders uaaHeaders = new HttpHeaders();
		HttpHeaders appHeaders = new HttpHeaders();
		uaaHeaders.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		appHeaders.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		// *** GET /app/id
		result = serverRunning.getForResponse("/id", appHeaders);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();

		cookie = result.getHeaders().getFirst("Set-Cookie");
		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		appHeaders.set("Cookie", cookie);

		assertTrue("Wrong location: " + location, location.contains("/oauth/authorize"));
		// *** GET /uaa/oauth/authorize
		result = serverRunning.getForResponse(location, uaaHeaders);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();

		cookie = result.getHeaders().getFirst("Set-Cookie");
		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		uaaHeaders.set("Cookie", cookie);

		assertTrue("Wrong location: " + location, location.contains("/login"));
		location = serverRunning.getAuthServerUrl("/login.do");

		MultiValueMap<String, String> formData;
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("username", testAccounts.getUserName());
		formData.add("password", testAccounts.getPassword());

		// *** POST /uaa/login.do
		result = serverRunning.postForResponse(location, uaaHeaders, formData);

		cookie = result.getHeaders().getFirst("Set-Cookie");
		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		uaaHeaders.set("Cookie", cookie);

		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();

		assertTrue("Wrong location: " + location, location.contains("/oauth/authorize"));
		// *** GET /uaa/oauth/authorize
		result = serverRunning.getForResponse(location, uaaHeaders);

		// If there is no token in place already for this client we get the approval page.
		// TODO: revoke the token so we always get the approval page
		if (result.getStatusCode() == HttpStatus.OK) {
			location = serverRunning.getAuthServerUrl("/oauth/authorize");

			formData = new LinkedMultiValueMap<String, String>();
			formData.add("user_oauth_approval", "true");

			// *** POST /uaa/oauth/authorize
			result = serverRunning.postForResponse(location, uaaHeaders, formData);
		}

		location = result.getHeaders().getLocation().toString();

		// SUCCESS
		assertTrue("Wrong location: " + location, location.contains("/id"));

		// *** GET /app/id
		result = serverRunning.getForResponse(location, appHeaders);
		// System.err.println(result.getHeaders());
		assertEquals(HttpStatus.OK, result.getStatusCode());
	}
}
