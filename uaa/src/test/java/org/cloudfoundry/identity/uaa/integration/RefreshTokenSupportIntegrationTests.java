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
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class RefreshTokenSupportIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

	@Rule
	public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

	private ResourceOwnerPasswordResourceDetails resource;

	@Before
	public void init() {
		resource = testAccounts.getDefaultResourceOwnerPasswordResource();
	}

	/**
	 * tests a happy-day flow of the refresh token grant
	 */
	@Test
	public void testTokenRefreshed() throws Exception {

		// add an approval for the scope requested
		{
			MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
			formData.add("grant_type", "password");
			formData.add("username", resource.getUsername());
			formData.add("password", resource.getPassword());
			formData.add("scope", "cloud_controller.read");
			HttpHeaders headers = new HttpHeaders();
			headers.set("Authorization",
					testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
			headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
			@SuppressWarnings("rawtypes")
			ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
			assertEquals(HttpStatus.OK, response.getStatusCode());
			assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

			@SuppressWarnings("unchecked")
			OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());

			HttpHeaders approvalHeaders = new HttpHeaders();
			approvalHeaders.set("Authorization", "bearer " + accessToken.getValue());
			ResponseEntity<Approval[]> approvals = serverRunning.getRestTemplate().exchange(
					serverRunning.getUrl("/approvals"),
					HttpMethod.PUT,
					new HttpEntity<Approval[]>((new Approval[]{new Approval(resource.getUsername(), resource.getClientId(),
							"cloud_controller.read", 50000, ApprovalStatus.APPROVED)}), approvalHeaders), Approval[].class);

			assertEquals(HttpStatus.OK, approvals.getStatusCode());
		}

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("username", resource.getUsername());
		formData.add("password", resource.getPassword());
		formData.add("scope", "cloud_controller.read");
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization",
				testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());

		// now use the refresh token to get a new access token.
		assertNotNull(accessToken.getRefreshToken());

		formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "refresh_token");
		formData.add("refresh_token", accessToken.getRefreshToken().getValue());
		response = serverRunning.postForMap("/oauth/token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
		@SuppressWarnings("unchecked")
		OAuth2AccessToken newAccessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
		try {
			JwtHelper.decode(newAccessToken.getValue());
		} catch (IllegalArgumentException e) {
			fail("Refreshed token was not a JWT");
		}
		assertFalse("New access token should be different to the old one.",
				newAccessToken.getValue().equals(accessToken.getValue()));

	}
}
