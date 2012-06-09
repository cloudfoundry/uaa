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

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
public class UaaAuthorizationRequestFactoryTests {
	
	private UaaAuthorizationRequestFactory factory;
	
	private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
	
	private Map<String,String> parameters = new HashMap<String, String>();

	private Map<String,String> approvalParameters = new HashMap<String, String>();

	private BaseClientDetails client = new BaseClientDetails();
	
	{
		factory = new UaaAuthorizationRequestFactory(clientDetailsService);
		Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(client);
	}

	@Test
	public void testFactoryProducesSomething() {
		assertNotNull(factory.createAuthorizationRequest(parameters, approvalParameters, "foo", "password", null));
	}

	@Test
	public void testScopeDefaultsToAuthoritiesForClientCredentials() {
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz"));
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters, approvalParameters, "foo", "client_credentials", null);
		assertEquals(StringUtils.commaDelimitedListToSet("foo.bar,spam.baz"), request.getScope());
	}

	@Test
	public void testResourecIdsExtracted() {
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz"));
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters, approvalParameters, "foo", "client_credentials", null);
		assertEquals(StringUtils.commaDelimitedListToSet("foo,spam"), request.getResourceIds());
	}

	@Test
	public void testResourecIdsWithCustomSeparator() {
		factory.setScopeSeparator("--");
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo--bar,spam--baz"));
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters, approvalParameters, "foo", "client_credentials", null);
		assertEquals(StringUtils.commaDelimitedListToSet("foo,spam"), request.getResourceIds());
	}

}
