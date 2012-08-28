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

import static org.junit.Assert.assertNotSame;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class UaaAuthenticationKeyGeneratorTests {

	private UaaAuthenticationKeyGenerator generator = new UaaAuthenticationKeyGenerator();

	private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);

	private AuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest("client", Arrays.asList("read",
			"write"));

	private UaaAuthentication userAuthentication = UaaAuthenticationTestFactory.getAuthentication("FOO", "foo",
			"foo@test.org");

	@Before
	public void init() {
		ClientDetails client = new BaseClientDetails("client", "none", "read,write", "authorization_code", "uaa.none");
		Mockito.when(clientDetailsService.loadClientByClientId("client")).thenReturn(client);
		generator.setClientDetailsService(clientDetailsService);
	}

	@Test
	public void testEmailChanges() {
		String key1 = generator.extractKey(new OAuth2Authentication(authorizationRequest, userAuthentication));
		userAuthentication = UaaAuthenticationTestFactory.getAuthentication("FOO", "foo", "foo@none.org");
		String key2 = generator.extractKey(new OAuth2Authentication(authorizationRequest, userAuthentication));
		assertNotSame(key1, key2);
	}

}
