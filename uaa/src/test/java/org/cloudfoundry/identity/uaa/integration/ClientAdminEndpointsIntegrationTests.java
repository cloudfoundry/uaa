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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.SecretChangeRequest;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class ClientAdminEndpointsIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

	@Rule
	public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

	@Before
	public void setUp() {
		Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));
	}

	@Test
	public void testGetClient() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/vmc", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().contains("vmc"));
	}

	@Test
	public void testListClients() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		// System.err.println(result.getBody());
		assertTrue(result.getBody().contains("vmc\":{"));
		assertFalse(result.getBody().contains("secret\":"));
	}

	@Test
	public void testCreateClient() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "client_credentials", "uaa.none");
		client.setClientSecret("clientSecret");
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);
		assertEquals(HttpStatus.CREATED, result.getStatusCode());

	}

	@Test
	public void nonImplicitGrantClientWithoutSecretIsRejected() throws Exception {
		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");
		HttpHeaders headers = getAuthenticatedHeaders(token);
		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "client_credentials", "uaa.none");
		ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
				serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
				new HttpEntity<BaseClientDetails>(client, headers), UaaException.class);
		assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
		assertEquals("invalid_client", result.getBody().getErrorCode());
	}

	@Test
	public void implicitAndAuthCodeGrantClient() throws Exception {
		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");
		HttpHeaders headers = getAuthenticatedHeaders(token);
		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "implicit,authorization_code", "uaa.none");
		ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
				serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
				new HttpEntity<BaseClientDetails>(client, headers), UaaException.class);
		assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
		assertEquals("invalid_client", result.getBody().getErrorCode());
	}

	@Test
	public void implicitGrantClientWithoutSecretIsOk() throws Exception {
		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");
		HttpHeaders headers = getAuthenticatedHeaders(token);
		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "implicit", "uaa.none");
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);

		assertEquals(HttpStatus.CREATED, result.getStatusCode());
	}

	@Test
	public void testUpdateClient() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");

		HttpHeaders headers = getAuthenticatedHeaders(token);

		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "client_credentials", "uaa.none");
		client.setClientSecret("clientSecret");
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);
		assertEquals(HttpStatus.CREATED, result.getStatusCode());

		client.setResourceIds(Collections.singleton("foo"));
		client.setClientSecret(null);

		result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/{client}"),
				HttpMethod.PUT, new HttpEntity<BaseClientDetails>(client, headers), Void.class, client.getClientId());
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());

	}

	@Test
	public void testChangeSecret() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write,clients.secret");

		HttpHeaders headers = getAuthenticatedHeaders(token);

		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "client_credentials", "uaa.none");
		client.setClientSecret("secret");
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);
		assertEquals(HttpStatus.CREATED, result.getStatusCode());

		client.setResourceIds(Collections.singleton("foo"));

		SecretChangeRequest change = new SecretChangeRequest();
		change.setOldSecret(client.getClientSecret());
		change.setSecret("newsecret");
		result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/{client}/secret"),
				HttpMethod.PUT, new HttpEntity<SecretChangeRequest>(change, headers), Void.class, client.getClientId());
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());

	}

	@Test
	public void testDeleteClient() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");

		HttpHeaders headers = getAuthenticatedHeaders(token);

		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "client_credentials", "uaa.none");
		client.setClientSecret("clientSecret");
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);
		assertEquals(HttpStatus.CREATED, result.getStatusCode());

		client.setResourceIds(Collections.singleton("foo"));

		result = serverRunning.getRestTemplate()
				.exchange(serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
						new HttpEntity<BaseClientDetails>(client, headers), Void.class, client.getClientId());
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());

	}

	@Test
	// CFID-372
	public void testCreateExistingClientFails() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");

		HttpHeaders headers = getAuthenticatedHeaders(token);

		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "client_credentials", "uaa.none");
		client.setClientSecret("clientSecret");
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);
		assertEquals(HttpStatus.CREATED, result.getStatusCode());

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> attempt = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Map.class);
		assertEquals(HttpStatus.CONFLICT, attempt.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String,String> map = attempt.getBody();
		assertEquals("invalid_client", map.get("error"));
	}

	public HttpHeaders getAuthenticatedHeaders(OAuth2AccessToken token) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set("Authorization", "Bearer " + token.getValue());
		return headers;
	}

	private OAuth2AccessToken getClientCredentialsAccessToken(String scope) throws Exception {

		String clientId = testAccounts.getAdminClientId();
		String clientSecret = testAccounts.getAdminClientSecret();

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "client_credentials");
		formData.add("client_id", clientId);
		formData.add("scope", scope);
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization",
				"Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
		return accessToken;

	}

}
