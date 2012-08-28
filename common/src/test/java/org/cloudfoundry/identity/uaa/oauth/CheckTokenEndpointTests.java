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
import java.util.Date;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.junit.Test;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;

/**
 * @author Dave Syer
 * 
 */
public class CheckTokenEndpointTests {

	private CheckTokenEndpoint endpoint = new CheckTokenEndpoint();

	private InMemoryTokenStore tokenStore = new InMemoryTokenStore();

	private OAuth2Authentication authentication;

	private int expiresIn;

	public CheckTokenEndpointTests() {
		authentication = new OAuth2Authentication(new DefaultAuthorizationRequest("client", Collections.singleton("read")),
				UaaAuthenticationTestFactory.getAuthentication("12345", "olds", "olds@vmware.com"));
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore);
		endpoint.setTokenServices(tokenServices);
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		token.setExpiration(new Date(System.currentTimeMillis() + 100000));
		expiresIn = token.getExpiresIn();
		tokenStore.storeAccessToken(token, authentication);
	}

	@Test
	public void testUserIdInResult() {
		Map<String, ?> result = endpoint.checkToken("FOO");
		assertEquals("olds", result.get("user_name"));
		assertEquals("12345", result.get("user_id"));
	}

	@Test
	public void testEmailInResult() {
		Map<String, ?> result = endpoint.checkToken("FOO");
		assertEquals("olds@vmware.com", result.get("email"));
	}

	@Test
	public void testClientIdInResult() {
		Map<String, ?> result = endpoint.checkToken("FOO");
		assertEquals("client", result.get("client_id"));
	}

	@Test
	public void testExpiryResult() {
		Map<String, ?> result = endpoint.checkToken("FOO");
		assertTrue(expiresIn + System.currentTimeMillis()/1000 >= Integer.parseInt(String.valueOf(result.get("exp"))));
	}

	@Test
	public void testUserAuthoritiesNotInResult() {
		Map<String, ?> result = endpoint.checkToken("FOO");
		assertEquals(null, result.get("user_authorities"));
	}

	@Test
	public void testClientAuthoritiesNotInResult() {
		Map<String, ?> result = endpoint.checkToken("FOO");
		assertEquals(null, result.get("client_authorities"));
	}

	@Test(expected = InvalidTokenException.class)
	public void testExpiredToken() throws Exception {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		token.setExpiration(new Date(System.currentTimeMillis() - 100000));
		expiresIn = token.getExpiresIn();
		tokenStore.storeAccessToken(token, authentication);
		Map<String, ?> result = endpoint.checkToken("FOO");
		assertEquals("expired_token", result.get("error"));
	}

	@Test
	public void testClientOnly() {
		authentication = new OAuth2Authentication(new DefaultAuthorizationRequest("client", Collections.singleton("read")), null);
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore);
		endpoint.setTokenServices(tokenServices);
		OAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		tokenStore.storeAccessToken(token, authentication);
		Map<String, ?> result = endpoint.checkToken("FOO");
		assertEquals("client", result.get("client_id"));
	}

}
