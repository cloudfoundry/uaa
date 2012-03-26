/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class RefreshTokenSupportIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private TestAccounts testAccounts = TestAccounts.standard(serverRunning);

	/**
	 * tests a happy-day flow of the refresh token grant
	 */
	@Test
	public void testTokenRefreshed() throws Exception {

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
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = OAuth2AccessToken.valueOf(response.getBody());

		// now use the refresh token to get a new access token.
		assertNotNull(accessToken.getRefreshToken());
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "refresh_token");
		formData.add("refresh_token", accessToken.getRefreshToken().getValue());
		response = serverRunning.postForMap("/oauth/token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
		@SuppressWarnings("unchecked")
		OAuth2AccessToken newAccessToken = OAuth2AccessToken.valueOf(response.getBody());
		assertFalse("TODO: This occasionally fails because the expiry time has 1 second accuracy.", newAccessToken.getValue()
				.equals(accessToken.getValue()));

	}
}
