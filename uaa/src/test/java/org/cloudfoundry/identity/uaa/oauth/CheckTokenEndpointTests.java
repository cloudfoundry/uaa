/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.junit.Test;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
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
		authentication = new OAuth2Authentication(new AuthorizationRequest("client", Collections.singleton("read"), null, null),
				UaaAuthenticationTestFactory.getAuthentication("12345", "olds", "olds@vmware.com"));
		endpoint.setTokenStore(tokenStore);
		OAuth2AccessToken token = new OAuth2AccessToken("FOO");
		token.setExpiration(new Date(System.currentTimeMillis()+100000));
		expiresIn = token.getExpiresIn();
		tokenStore.storeAccessToken(token, authentication);
	}

	@Test
	public void testUserIdInResult() {
		Map<String, Object> result = endpoint.checkToken("FOO");
		assertEquals("olds", result.get("user_id"));
	}

	@Test
	public void testEmailInResult() {
		Map<String, Object> result = endpoint.checkToken("FOO");
		assertEquals("olds@vmware.com", result.get("email"));
	}

	@Test
	public void testClientIdInResult() {
		Map<String, Object> result = endpoint.checkToken("FOO");
		assertEquals("client", result.get("client_id"));
	}

	@Test
	public void testExpiryResult() {
		Map<String, Object> result = endpoint.checkToken("FOO");
		assertTrue(expiresIn >= Integer.parseInt(String.valueOf(result.get("expires_in"))));
	}

	@Test
	public void testAuthoritiesInResult() {
		Map<String, Object> result = endpoint.checkToken("FOO");
		assertEquals(Arrays.asList("ROLE_USER"), result.get("user_authorities"));
	}
	
	@Test
	public void testExpiredToken() throws Exception {
		OAuth2AccessToken token = new OAuth2AccessToken("FOO");
		token.setExpiration(new Date(System.currentTimeMillis()-100000));
		expiresIn = token.getExpiresIn();
		tokenStore.storeAccessToken(token, authentication);
		Map<String, Object> result = endpoint.checkToken("FOO");
		assertEquals("expired_token", result.get("error"));
	}

	@Test
	public void testClientOnly() {
		authentication = new OAuth2Authentication(new AuthorizationRequest("client", Collections.singleton("read"), null, null), null);
		endpoint.setTokenStore(tokenStore);
		OAuth2AccessToken token = new OAuth2AccessToken("FOO");
		tokenStore.storeAccessToken(token, authentication);
		Map<String, Object> result = endpoint.checkToken("FOO");
		assertEquals("client", result.get("client_id"));
	}

}
