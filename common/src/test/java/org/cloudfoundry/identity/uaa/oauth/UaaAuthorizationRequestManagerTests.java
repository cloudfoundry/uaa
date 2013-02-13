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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.StubSecurityContextAccessor;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
public class UaaAuthorizationRequestManagerTests {

	private UaaAuthorizationRequestManager factory;

	private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);

	private Map<String, String> parameters = new HashMap<String, String>();

	private BaseClientDetails client = new BaseClientDetails();

	@Before
	public void init() {
		parameters.put("client_id", "foo");
		factory = new UaaAuthorizationRequestManager(clientDetailsService);
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
		factory.validateParameters(request.getAuthorizationParameters(), client);
	}

	@Test
	public void testOpenidScopeIncludeIsAResourceId() {
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
		parameters.put("scope", "openid foo.bar");
		factory.setDefaultScopes(Arrays.asList("openid"));
		factory.setSecurityContextAccessor(securityContextAccessor);
		client.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
		assertEquals(StringUtils.commaDelimitedListToSet("openid,foo.bar"), new TreeSet<String>(request.getScope()));
		assertEquals(StringUtils.commaDelimitedListToSet("openid,foo"), new TreeSet<String>(request.getResourceIds()));
	}

	@Test
	public void testEmptyScopeOkForClientWithNoScopes() {
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
		client.setScope(StringUtils.commaDelimitedListToSet("")); // empty
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
		assertEquals(StringUtils.commaDelimitedListToSet(""), new TreeSet<String>(request.getScope()));
	}

	@Test(expected=InvalidScopeException.class)
	public void testEmptyScopeFailsClientWithScopes() {
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
		client.setScope(StringUtils.commaDelimitedListToSet("one,two")); // not empty
		AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
		assertEquals(StringUtils.commaDelimitedListToSet(""), new TreeSet<String>(request.getScope()));
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
		client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none,spam.baz"));
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

	@Test(expected=BadClientCredentialsException.class)
	public void tesstWrongClientId() {
		parameters.put("grant_type", "authorization_code");
		parameters.put("client_id", "bar");
		parameters.put("scope", "read");
		factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write", "implicit", null));
	}
}
