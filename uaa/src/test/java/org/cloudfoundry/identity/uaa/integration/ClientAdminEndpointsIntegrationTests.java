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
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
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
import org.springframework.security.core.authority.AuthorityUtils;
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

	private OAuth2AccessToken token;
	private HttpHeaders headers;

	@Before
	public void setUp() throws Exception {
		Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));
		token = getClientCredentialsAccessToken("clients.read,clients.write");
		headers = getAuthenticatedHeaders(token);
	}

	@Test
	public void testGetClient() throws Exception {
		HttpHeaders headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/vmc", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().contains("vmc"));
	}

	@Test
	public void testListClients() throws Exception {
		HttpHeaders headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		// System.err.println(result.getBody());
		assertTrue(result.getBody().contains("\"client_id\":\"vmc\""));
		assertFalse(result.getBody().contains("secret\":"));
	}

	@Test
	public void testCreateClient() throws Exception {
		createClient("client_credentials");
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
		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "implicit,authorization_code", "uaa.none");
		ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
				serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
				new HttpEntity<BaseClientDetails>(client, headers), UaaException.class);
		assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
		assertEquals("invalid_client", result.getBody().getErrorCode());
	}

	@Test
	public void implicitGrantClientWithoutSecretIsOk() throws Exception {
		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "implicit", "uaa.none");
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);

		assertEquals(HttpStatus.CREATED, result.getStatusCode());
	}

    @Test
    public void passwordGrantClientWithoutSecretIsOk() throws Exception {
        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", "password", "uaa.none");
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);

        assertEquals(HttpStatus.CREATED, result.getStatusCode());
    }

	@Test
	public void authzCodeGrantAutomaticallyAddsRefreshToken() throws Exception {
		BaseClientDetails client = createClient("authorization_code");

		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().contains("\"authorized_grant_types\":[\"authorization_code\",\"refresh_token\"]"));
	}

    @Test
    public void passwordGrantAutomaticallyAddsRefreshToken() throws Exception {
        BaseClientDetails client = createClient("password");

        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody().contains("\"authorized_grant_types\":[\"password\",\"refresh_token\"]"));
    }

    @Test
	public void testUpdateClient() throws Exception {
		BaseClientDetails client = createClient("client_credentials");

		client.setResourceIds(Collections.singleton("foo"));
		client.setClientSecret(null);
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("some.crap"));
		client.setAccessTokenValiditySeconds(60);
		client.setRefreshTokenValiditySeconds(120);
		client.setAdditionalInformation(Collections.<String,Object>singletonMap("foo", Arrays.asList("rab")));

		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/{client}"),
				HttpMethod.PUT, new HttpEntity<BaseClientDetails>(client, headers), Void.class, client.getClientId());
		assertEquals(HttpStatus.OK, result.getStatusCode());

		ResponseEntity<String> response = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		String body = response.getBody();
		assertTrue(body.contains(client.getClientId()));
		assertTrue(body.contains("some.crap"));
		assertTrue(body.contains("refresh_token_validity\":120"));
		assertTrue(body.contains("access_token_validity\":60"));
		assertTrue("Wrong body: " + body, body.contains("\"foo\":[\"rab\"]"));

	}

	@Test
	public void testChangeSecret() throws Exception {
		headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.secret"));
		BaseClientDetails client = createClient("client_credentials");

		client.setResourceIds(Collections.singleton("foo"));

		SecretChangeRequest change = new SecretChangeRequest();
		change.setOldSecret(client.getClientSecret());
		change.setSecret("newsecret");
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/{client}/secret"),
				HttpMethod.PUT, new HttpEntity<SecretChangeRequest>(change, headers), Void.class, client.getClientId());
		assertEquals(HttpStatus.OK, result.getStatusCode());
	}

	@Test
	public void testDeleteClient() throws Exception {
		BaseClientDetails client = createClient("client_credentials");

		client.setResourceIds(Collections.singleton("foo"));

		ResponseEntity<Void> result = serverRunning.getRestTemplate()
				.exchange(serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
						new HttpEntity<BaseClientDetails>(client, headers), Void.class, client.getClientId());
		assertEquals(HttpStatus.OK, result.getStatusCode());
	}

	@Test
	// CFID-372
	public void testCreateExistingClientFails() throws Exception {
		BaseClientDetails client = createClient("client_credentials");

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> attempt = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Map.class);
		assertEquals(HttpStatus.CONFLICT, attempt.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String,String> map = attempt.getBody();
		assertEquals("invalid_client", map.get("error"));
	}

	private BaseClientDetails createClient(String grantTypes) throws Exception {
		BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar", grantTypes, "uaa.none");
		client.setClientSecret("secret");
		client.setAdditionalInformation(Collections.<String,Object>singletonMap("foo", Arrays.asList("bar")));
		ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
				HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);
		assertEquals(HttpStatus.CREATED, result.getStatusCode());
		return client;
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
