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
import static org.junit.Assert.assertNotNull;

import java.util.Collection;
import java.util.Collections;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;

/**
 * @author Dave Syer
 * 
 */
public class TokenAdminEndpointsTests {

	private TokenAdminEndpoints endpoints = new TokenAdminEndpoints();

	private ConsumerTokenServices tokenServices = Mockito.mock(ConsumerTokenServices.class);

	private ScimUserProvisioning scimProvisioning = Mockito.mock(ScimUserProvisioning.class);

	private AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(Collections.singletonMap("client_id",
			"foo"));

	{
		endpoints.setTokenServices(tokenServices);
		endpoints.setScimUserProvisioning(scimProvisioning);
	}

	@Test
	public void testListTokensForOAuth2User() throws Exception {
		Mockito.when(tokenServices.findTokensByUserName("marissa")).thenReturn(
				Collections.<OAuth2AccessToken> singleton(new DefaultOAuth2AccessToken("FOO")));
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForUser("marissa", new OAuth2Authentication(
				authorizationRequest, new TestingAuthenticationToken("marissa", "")), false);
		assertEquals(1, tokens.size());
		assertNotNull(tokens.iterator().next().getAdditionalInformation().get(JwtTokenEnhancer.TOKEN_ID));
	}

	@Test
	public void testListTokensForOAuth2UserWithClientId() throws Exception {
		Mockito.when(tokenServices.findTokensByUserName("marissa")).thenReturn(
				Collections.<OAuth2AccessToken> singleton(new DefaultOAuth2AccessToken("FOO")));
		Mockito.when(tokenServices.getClientId("FOO")).thenReturn("foo");
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForUser("marissa", new OAuth2Authentication(
				authorizationRequest, new TestingAuthenticationToken("marissa", "")), false);
		assertEquals(1, tokens.size());
		assertNotNull(tokens.iterator().next().getAdditionalInformation().get(JwtTokenEnhancer.TOKEN_ID));
	}

	@Test
	public void testListTokensForOAuth2UserByClient() throws Exception {
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForUser("marissa", new OAuth2Authentication(
				authorizationRequest, null), false);
		assertEquals(0, tokens.size());
	}

	@Test
	public void testListTokensForUser() throws Exception {
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForUser("marissa", new TestingAuthenticationToken(
				"marissa", ""), false);
		assertEquals(0, tokens.size());
	}

	@Test
	public void testListTokensForUserId() throws Exception {
		Mockito.when(scimProvisioning.retrieveUser("12345")).thenReturn(
				new ScimUser("12345", "marissa", "Marissa", "Bloggs"));
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForUser("12345", new TestingAuthenticationToken(
				"marissa", ""), true);
		assertEquals(0, tokens.size());
	}

	@Test
	public void testRevokeTokenForUser() throws Exception {
		Mockito.when(tokenServices.findTokensByUserName("marissa")).thenReturn(
				Collections.<OAuth2AccessToken> singleton(new DefaultOAuth2AccessToken("FOO")));
		Mockito.when(tokenServices.revokeToken("FOO")).thenReturn(true);
		ResponseEntity<Void> result = endpoints.revokeUserToken("marissa", new StandardPasswordEncoder().encode("FOO"),
				new TestingAuthenticationToken("marissa", ""), false);
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
	}

	@Test
	public void testRevokeTokenForUserWithTokenId() throws Exception {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		token.setAdditionalInformation(Collections.<String, Object> singletonMap(JwtTokenEnhancer.TOKEN_ID, "BAR"));
		Mockito.when(tokenServices.findTokensByUserName("marissa")).thenReturn(
				Collections.<OAuth2AccessToken> singleton(token));
		Mockito.when(tokenServices.revokeToken("FOO")).thenReturn(true);
		ResponseEntity<Void> result = endpoints.revokeUserToken("marissa", "BAR", new TestingAuthenticationToken(
				"marissa", ""), false);
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
	}

	@Test
	public void testRevokeInvalidTokenForUser() throws Exception {
		OAuth2AccessToken token = new DefaultOAuth2AccessToken("BAR");
		Mockito.when(tokenServices.findTokensByUserName("marissa")).thenReturn(Collections.singleton(token));
		ResponseEntity<Void> result = endpoints.revokeUserToken("marissa", "FOO", new TestingAuthenticationToken(
				"marissa", ""), false);
		assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
	}

	@Test
	public void testRevokeNullTokenForUser() throws Exception {
		ResponseEntity<Void> result = endpoints.revokeUserToken("marissa", null, new TestingAuthenticationToken(
				"marissa", ""), false);
		assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
	}

	@Test(expected = AccessDeniedException.class)
	public void testListTokensForWrongUser() throws Exception {
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForUser("barry", new TestingAuthenticationToken(
				"marissa", ""), false);
		assertEquals(0, tokens.size());
	}

	@Test(expected = AccessDeniedException.class)
	public void testListTokensForWrongOAuth2User() throws Exception {
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForUser("barry", new OAuth2Authentication(
				authorizationRequest, new TestingAuthenticationToken("marissa", "")), false);
		assertEquals(0, tokens.size());
	}

	@Test
	public void testListTokensForClient() throws Exception {
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForClient("foo", new OAuth2Authentication(
				authorizationRequest, null));
		assertEquals(0, tokens.size());
	}

	@Test(expected = AccessDeniedException.class)
	public void testListTokensForWrongClient() throws Exception {
		Collection<OAuth2AccessToken> tokens = endpoints.listTokensForClient("bar", new OAuth2Authentication(
				authorizationRequest, null));
		assertEquals(0, tokens.size());
	}

	@Test
	public void testRevokeTokenForClient() throws Exception {
		Mockito.when(tokenServices.findTokensByClientId("foo")).thenReturn(
				Collections.<OAuth2AccessToken> singleton(new DefaultOAuth2AccessToken("FOO")));
		Mockito.when(tokenServices.revokeToken("FOO")).thenReturn(true);
		ResponseEntity<Void> result = endpoints.revokeClientToken("foo", new StandardPasswordEncoder().encode("FOO"),
				new TestingAuthenticationToken("foo", ""));
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
	}

	@Test
	public void testRevokeInvalidTokenForClient() throws Exception {
		ResponseEntity<Void> result = endpoints.revokeClientToken("foo", "FOO", new TestingAuthenticationToken("foo",
				""));
		assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
	}

}
