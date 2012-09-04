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

package org.cloudfoundry.identity.uaa.scim;

import static org.junit.internal.matchers.StringContains.containsString;

import java.util.Collection;

import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * @author Dave Syer
 * 
 */
public class GroupsUsersEndpointsTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private GroupsUsersEndpoints endpoints = new GroupsUsersEndpoints();

	private SecurityContextAccessor securityContextAccessor = Mockito.mock(SecurityContextAccessor.class);

	private ScimUserEndpoints scimUserEndpoints = Mockito.mock(ScimUserEndpoints.class);

	@SuppressWarnings("rawtypes")
	private Collection authorities = (Collection) AuthorityUtils.commaSeparatedStringToAuthorityList("orgs.foo,uaa.user");

	@SuppressWarnings("unchecked")
	@Before
	public void init() {
		endpoints.setSecurityContextAccessor(securityContextAccessor);
		endpoints.setScimUserEndpoints(scimUserEndpoints);
		Mockito.when(securityContextAccessor.getAuthorities()).thenReturn(authorities);
	}

	@Test
	public void testDefaultFilterHappyDay() {
		endpoints.findUsers("orgs.foo", "", "ascending", 0, 100);
	}

	@Test
	public void testDefaultFilterWrongGroup() {
		expected.expect(ScimException.class);
		expected.expectMessage(containsString("Current user"));
		endpoints.findUsers("orgs.bar", "", "ascending", 0, 100);
	}

	@Test
	public void testBadFieldInFilter() {
		expected.expect(ScimException.class);
		expected.expectMessage(containsString("Invalid filter"));
		endpoints.findUsers("orgs.foo", "emails.value eq 'foo@bar.org'", "ascending", 0, 100);
	}

	@Test
	public void testBadFilterWithGroup() {
		expected.expect(ScimException.class);
		expected.expectMessage(containsString("Invalid filter"));
		endpoints.findUsers("orgs.foo", "groups.display co 'foo'", "ascending", 0, 100);
	}

	@Test
	public void testBadGroup() {
		expected.expect(ScimException.class);
		expected.expectMessage(containsString("Current user"));
		endpoints.findUsers("uaa.user", "", "ascending", 0, 100);
	}

}
