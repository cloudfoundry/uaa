/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.scim;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.internal.matchers.StringContains.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Dave Syer
 * @author Luke Taylor
 *
 */
public class ScimUserEndpointsTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private static ScimUser joel;
	private static ScimUser dale;
	private static ScimUserEndpoints endpoints;
	private static InMemoryScimUserProvisioning dao;

	@BeforeClass
	public static void setUp() {
		dao = new InMemoryScimUserProvisioning(new HashMap<String, UaaUser>());
		endpoints = new ScimUserEndpoints();
		endpoints.setScimUserProvisioning(dao);
		joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
		joel.addEmail("jdsa@vmware.com");
		dale = new ScimUser(null, "olds", "Dale", "Olds");
		dale.addEmail("olds@vmware.com");
		joel = dao.createUser(joel, "password");
		dale = dao.createUser(dale, "password");
	}

	@AfterClass
	public static void tearDown() throws Exception {
		dao.destroy();
	}

	@Test
	public void userCanChangeTheirOwnPasswordIfTheySupplyCorrectCurrentPassword() {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		String id = joel.getId();
		when(sca.getUserId()).thenReturn(id);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setOldPassword("password");
		change.setPassword("newpassword");
		endpoints.changePassword(id, change);
	}

	@Test(expected = ScimException.class)
	public void userCantChangeAnotherUsersPassword() {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getUserId()).thenReturn(joel.getId());
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setOldPassword("password");
		change.setPassword("newpassword");
		endpoints.changePassword(dale.getId(), change);
	}

	@Test
	public void adminCanChangeAnotherUsersPassword() {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getUserId()).thenReturn(dale.getId());
		when(sca.isAdmin()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test(expected = ScimException.class)
	public void changePasswordRequestFailsForUserWithoutCurrentPassword() {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		String id = joel.getId();
		when(sca.getUserId()).thenReturn(id);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(id, change);
	}

	@Test(expected = ScimException.class)
	public void changePasswordRequestFailsForAdminWithoutOwnCurrentPassword() {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		String id = joel.getId();
		when(sca.getUserId()).thenReturn(id);
		when(sca.isAdmin()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(id, change);
	}

	@Test
	public void clientCanChangeUserPasswordWithoutCurrentPassword() {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		String id = joel.getId();
		when(sca.isClient()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(id, change);
	}

	@Test(expected = BadCredentialsException.class)
	public void changePasswordFailsForUserIfTheySupplyWrongCurrentPassword() {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		String id = joel.getId();
		when(sca.getUserId()).thenReturn(id);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		change.setOldPassword("wrongpassword");
		endpoints.changePassword(id, change);
	}

	@Test
	public void testFindAllIds() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "id pr", 1, 100);
		assertEquals(2, results.getTotalResults());
	}

	@Test
	public void testFindAllNames() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("userName", "id pr", 1, 100);
		Collection<Object> values = getSetFromMaps(results.getResources(), "userName");
		assertTrue(values.contains("olds"));
	}

	@Test
	public void testFindAllEmails() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("emails.value", "id pr", 1, 100);
		Collection<Object> values = getSetFromMaps(results.getResources(), "emails.value");
		assertTrue(values.contains(Arrays.asList("olds@vmware.com")));
	}

	@Test
	public void testInvalidFilterExpression() {
		expected.expect(ScimException.class);
		expected.expectMessage(containsString("Invalid filter"));
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName qq 'd'", 1, 100);
		assertEquals(0, results.getTotalResults());
	}

	@Test
	public void testFindIdsByUserName() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName eq 'jdsa'", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
		assertEquals(joel.getId(), results.getResources().iterator().next().get("id"));
	}

	@Test
	public void testFindIdsByUserNameContains() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName co 'd'", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

//	@Test
//	public void testFindIdsByNameExists() {
//		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "name pr", 1, 100);
//		assertEquals(2, results.getTotalResults());
//	}

	@Test
	public void testFindIdsByUserNameStartWith() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName sw 'j'", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsByEmailContains() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "emails.value sw 'j'", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsByEmailContainsWithEmptyResult() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "emails.value sw 'z'", 1, 100);
		assertEquals(0, results.getTotalResults());
	}

	@Test
	public void testFindIdsWithBooleanExpression() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName co 'd' and id pr", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsWithBooleanExpressionIvolvingEmails() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName co 'd' and emails.value co 'vmware'", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	private Collection<Object> getSetFromMaps(Collection<Map<String, Object>> resources, String key) {
		Collection<Object> result = new ArrayList<Object>();
		for (Map<String, Object> map : resources) {
			result.add(map.get(key));
		}
		return result;
	}

}
