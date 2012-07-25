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
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
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

	private Map<String, String> parameters = new HashMap<String, String>();

	private BaseClientDetails client = new BaseClientDetails();

	@Before
	public void init() {
		parameters.put("client_id", "foo");
		factory = new UaaAuthorizationRequestFactory(clientDetailsService);
		factory.setSecurityContextAccessor(new StubSecurityContextAccessor());
		Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(client);
	}

	@Test
	public void testFactoryProducesSomething() {
		assertNotNull(factory.createAuthorizationRequest(parameters));
	}

	@Test
	public void testScopeDefaultsToAuthoritiesForClientCredentials() {
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz"));
		parameters.put("grant_type", "client_credentials");
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
		assertEquals(StringUtils.commaDelimitedListToSet("foo.bar,spam.baz"), request.getScope());
	}

	@Test
	public void testScopeIncludesAuthoritiesForUser() {
		SecurityContextAccessor securityContextAccessor = new StubSecurityContextAccessor() {
			@Override
			public boolean isUser() {
				return true;
			}

			@Override
			public Collection<? extends GrantedAuthority> getAuthorities() {
				return AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz");
			}
		};
		factory.setSecurityContextAccessor(securityContextAccessor);
		client.setScope(StringUtils.commaDelimitedListToSet("one,two,foo.bar"));
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
		assertEquals(StringUtils.commaDelimitedListToSet("foo.bar"), new TreeSet<String>(request.getScope()));
	}

	@Test
	public void testResourecIdsExtracted() {
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz"));
		parameters.put("grant_type", "client_credentials");
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
		assertEquals(StringUtils.commaDelimitedListToSet("foo,spam"), request.getResourceIds());
	}

	@Test
	public void testResourecIdsDoNotIncludeUaa() {
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.bar,spam.baz"));
		parameters.put("grant_type", "client_credentials");
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
		assertEquals(StringUtils.commaDelimitedListToSet("spam"), request.getResourceIds());
	}

	@Test
	public void testResourceIdsWithCustomSeparator() {
		factory.setScopeSeparator("--");
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo--bar,spam--baz"));
		parameters.put("grant_type", "client_credentials");
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
		assertEquals(StringUtils.commaDelimitedListToSet("foo,spam"), request.getResourceIds());
	}

	@Test
	public void testScopesValid() throws Exception {
		factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write", "implicit", null));
	}

	@Test(expected = InvalidScopeException.class)
	public void testScopesInvalid() throws Exception {
		parameters.put("scope", "admin");
		factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write", "implicit", null));
	}

	private static class StubSecurityContextAccessor implements SecurityContextAccessor {

		@Override
		public boolean isClient() {
			return false;
		}

		@Override
		public boolean isUser() {
			return false;
		}

		@Override
		public boolean isAdmin() {
			return false;
		}

		@Override
		public String getUserId() {
			return null;
		}

		@Override
		public String getClientId() {
			return null;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return Collections.emptySet();
		}

	}

}
