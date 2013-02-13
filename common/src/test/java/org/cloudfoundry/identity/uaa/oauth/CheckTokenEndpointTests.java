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
package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.oauth.token.SignerProvider;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenServices;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.junit.Test;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 *
 */
public class CheckTokenEndpointTests {

	private CheckTokenEndpoint endpoint = new CheckTokenEndpoint();

	private OAuth2Authentication authentication;

	private int expiresIn =  60 * 60 * 12;

	private OAuth2AccessToken accessToken = null;

	private UaaTokenServices tokenServices = new UaaTokenServices();

	private InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

	public CheckTokenEndpointTests() {
		authentication = new OAuth2Authentication(new DefaultAuthorizationRequest("client", Collections.singleton("read")),
				UaaAuthenticationTestFactory.getAuthentication("12345", "olds", "olds@vmware.com"));

		SignerProvider signerProvider = new SignerProvider();
		signerProvider.setSigningKey("abc");
		signerProvider.setVerifierKey("abc");
		tokenServices.setSignerProvider(signerProvider);
		endpoint.setTokenServices(tokenServices);
		UaaUserDatabase userDatabase = new MockUaaUserDatabase("12345", "olds", "olds@vmware.com", null, null);
		tokenServices.setUserDatabase(userDatabase);

		Map<String, ? extends ClientDetails> clientDetailsStore = Collections.singletonMap("client", new BaseClientDetails("client", "scim, cc","read, write", "authorization_code, password", "scim.read, scim.write", "http://localhost:8080/uaa"));
		clientDetailsService.setClientDetailsStore(clientDetailsStore);
		tokenServices.setClientDetailsService(clientDetailsService);

		accessToken = tokenServices.createAccessToken(authentication);
	}

	@Test
	public void testUserIdInResult() {
		Map<String, ?> result = endpoint.checkToken(accessToken.getValue());
		assertEquals("olds", result.get("user_name"));
		assertEquals("12345", result.get("user_id"));
	}

	@Test
	public void testEmailInResult() {
		Map<String, ?> result = endpoint.checkToken(accessToken.getValue());
		assertEquals("olds@vmware.com", result.get("email"));
	}

	@Test
	public void testClientIdInResult() {
		Map<String, ?> result = endpoint.checkToken(accessToken.getValue());
		assertEquals("client", result.get("client_id"));
	}

	@Test
	public void testExpiryResult() {
		Map<String, ?> result = endpoint.checkToken(accessToken.getValue());
		assertTrue(expiresIn + System.currentTimeMillis()/1000 >= Integer.parseInt(String.valueOf(result.get("exp"))));
	}

	@Test
	public void testUserAuthoritiesNotInResult() {
		Map<String, ?> result = endpoint.checkToken(accessToken.getValue());
		assertEquals(null, result.get("user_authorities"));
	}

	@Test
	public void testClientAuthoritiesNotInResult() {
		Map<String, ?> result = endpoint.checkToken(accessToken.getValue());
		assertEquals(null, result.get("client_authorities"));
	}

	@Test(expected = InvalidTokenException.class)
	public void testExpiredToken() throws Exception {
		BaseClientDetails clientDetails = new BaseClientDetails("client", "scim, cc","read, write", "authorization_code, password", "scim.read, scim.write", "http://localhost:8080/uaa");
		clientDetails.setAccessTokenValiditySeconds(1);
		Map<String, ? extends ClientDetails> clientDetailsStore = Collections.singletonMap("client", clientDetails);
		clientDetailsService.setClientDetailsStore(clientDetailsStore);
		tokenServices.setClientDetailsService(clientDetailsService);
		accessToken = tokenServices.createAccessToken(authentication);

		Thread.sleep(1000);

		Map<String, ?> result = endpoint.checkToken(accessToken.getValue());
		assertEquals("expired_token", result.get("error"));
	}

	@Test
	public void testClientOnly() {
		authentication = new OAuth2Authentication(new DefaultAuthorizationRequest("client", Collections.singleton("read")), null);
		accessToken = tokenServices.createAccessToken(authentication);
		Map<String, ?> result = endpoint.checkToken(accessToken.getValue());
		assertEquals("client", result.get("client_id"));
		assertEquals("client", result.get("user_id"));
	}

}
