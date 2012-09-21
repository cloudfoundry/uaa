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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.internal.matchers.StringContains.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.View;

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

	private static JdbcScimUserProvisioning dao;

	private static EmbeddedDatabase database;

	private List<ScimUser> createdUsers = new ArrayList<ScimUser>();

	@BeforeClass
	public static void setUp() {
		EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
		builder.addScript("classpath:/org/cloudfoundry/identity/uaa/schema-hsqldb.sql");
		database = builder.build();
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		dao = new JdbcScimUserProvisioning(jdbcTemplate);
		dao.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		dao.setPasswordValidator(new NullPasswordValidator());
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
		if (database != null) {
			database.shutdown();
		}
	}

	@After
	public void cleanUp() {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		for (ScimUser user : createdUsers) {
			jdbcTemplate.update("delete from users where id=?", user.getId());
		}
	}

	@Test
	public void userGetsADefaultPassword() {
		ScimUser user = new ScimUser(null, "dave", "David", "Syer");
		user.addEmail("dsyer@vmware.com");
		endpoints.setSecurityContextAccessor(mockSecurityContext(user));
		ScimUser created = endpoints.createUser(user);
		createdUsers.add(created);
		assertNull("A newly created user revealed its password", created.getPassword());
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		String password = jdbcTemplate.queryForObject("select password from users where id=?", String.class,
				created.getId());
		// Generated password...
		assertNotNull(password);
	}

	@Test
	public void userWithNoEmailNotAllowed() {
		ScimUser user = new ScimUser(null, "dave", "David", "Syer");
		endpoints.setSecurityContextAccessor(mockSecurityContext(user));
		try {
			endpoints.createUser(user);
			fail("Expected InvalidUserException");
		}
		catch (InvalidUserException e) {
			// expected
			String message = e.getMessage();
			assertTrue("Wrong message: " + message, message.contains("email"));
		}
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		int count = jdbcTemplate.queryForInt("select count(*) from users where userName=?", "dave");
		assertEquals(0, count);
	}

	@Test
	public void testHandleExceptionWithConstraintViolation() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		endpoints.setMessageConverters(new HttpMessageConverter<?>[] { new ExceptionReportHttpMessageConverter() });
		View view = endpoints.handleException(new DataIntegrityViolationException("foo"), request);
		ConvertingExceptionView converted = (ConvertingExceptionView) view;
		converted.render(Collections.<String, Object> emptyMap(), request, response);
		String body = response.getContentAsString();
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
		// System.err.println(body);
		assertTrue("Wrong body: " + body, body.contains("message\":\"foo"));
	}

	@Test
	public void testHandleExceptionWithBadFieldName() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		endpoints.setMessageConverters(new HttpMessageConverter<?>[] { new ExceptionReportHttpMessageConverter() });
		View view = endpoints.handleException(new HttpMessageConversionException("foo"), request);
		ConvertingExceptionView converted = (ConvertingExceptionView) view;
		converted.render(Collections.<String, Object> emptyMap(), request, response);
		String body = response.getContentAsString();
		assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
		// System.err.println(body);
		assertTrue("Wrong body: " + body, body.contains("message\":\"foo"));
	}

	@Test
	public void userCanInitializePassword() {
		ScimUser user = new ScimUser(null, "dave", "David", "Syer");
		user.addEmail("dsyer@vmware.com");
		ReflectionTestUtils.setField(user, "password", "foo");
		endpoints.setSecurityContextAccessor(mockSecurityContext(user));
		ScimUser created = endpoints.createUser(user);
		createdUsers.add(created);
		assertNull("A newly created user revealed its password", created.getPassword());
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		String password = jdbcTemplate.queryForObject("select password from users where id=?", String.class,
				created.getId());
		assertEquals("foo", password);
	}

	@Test
	public void userCanChangeTheirOwnPasswordIfTheySupplyCorrectCurrentPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setOldPassword("password");
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test(expected = ScimException.class)
	public void userCantChangeAnotherUsersPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setOldPassword("password");
		change.setPassword("newpassword");
		endpoints.changePassword(dale.getId(), change);
	}

	@Test
	public void adminCanChangeAnotherUsersPassword() {
		SecurityContextAccessor sca = mockSecurityContext(dale);
		when(sca.isAdmin()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test(expected = ScimException.class)
	public void changePasswordRequestFailsForUserWithoutCurrentPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test(expected = ScimException.class)
	public void changePasswordRequestFailsForAdminWithoutOwnCurrentPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test
	public void clientCanChangeUserPasswordWithoutCurrentPassword() {
		SecurityContextAccessor sca = mockSecurityContext(joel);
		when(sca.isClient()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test(expected = BadCredentialsException.class)
	public void changePasswordFailsForUserIfTheySupplyWrongCurrentPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		change.setOldPassword("wrongpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test
	public void deleteIsAllowedWithCorrectVersionInEtag() {
		ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
		exGuy.addEmail("exguy@imonlyheretobedeleted.com");
		exGuy = dao.createUser(exGuy, "exguyspassword");
		createdUsers.add(exGuy);
		endpoints.deleteUser(exGuy.getId(), Integer.toString(exGuy.getMeta().getVersion()));
	}

	@Test(expected = OptimisticLockingFailureException.class)
	public void deleteIsNotAllowedWithWrongVersionInEtag() {
		ScimUser exGuy = new ScimUser(null, "deleteme2", "Expendable", "Guy");
		exGuy.addEmail("exguy2@imonlyheretobedeleted.com");
		exGuy = dao.createUser(exGuy, "exguyspassword");
		createdUsers.add(exGuy);
		endpoints.deleteUser(exGuy.getId(), Integer.toString(exGuy.getMeta().getVersion() + 1));
	}

	@Test
	public void deleteIsAllowedWithNullEtag() {
		ScimUser exGuy = new ScimUser(null, "deleteme3", "Expendable", "Guy");
		exGuy.addEmail("exguy3@imonlyheretobedeleted.com");
		exGuy = dao.createUser(exGuy, "exguyspassword");
		createdUsers.add(exGuy);
		endpoints.deleteUser(exGuy.getId(), null);
	}

	private SecurityContextAccessor mockSecurityContext(ScimUser user) {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		String id = user.getId();
		when(sca.getUserId()).thenReturn(id);
		return sca;
	}

	@Test
	public void testFindAllIds() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
	}

	@Test
	public void testFindPageOfIds() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "id pr", null, "ascending", 1, 1);
		assertEquals(2, results.getTotalResults());
		assertEquals(1, results.getResources().size());
	}

	@Test
	public void testFindAllNames() {
		SearchResults<Map<String, Object>> results = endpoints
				.findUsers("userName", "id pr", null, "ascending", 1, 100);
		Collection<Object> values = getSetFromMaps(results.getResources(), "userName");
		assertTrue(values.contains("olds"));
	}

	@Test
	public void testFindAllEmails() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("emails.value", "id pr", null, "ascending", 1,
				100);
		Collection<Object> values = getSetFromMaps(results.getResources(), "emails.value");
		assertTrue(values.contains(Arrays.asList("olds@vmware.com")));
	}

	@Test
	public void testInvalidFilterExpression() {
		expected.expect(ScimException.class);
		expected.expectMessage(containsString("Invalid filter"));
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName qq 'd'", null, "ascending", 1,
				100);
		assertEquals(0, results.getTotalResults());
	}

	@Test
	public void testFindIdsByUserName() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName eq 'jdsa'", null, "ascending",
				1, 100);
		assertEquals(1, results.getTotalResults());
		assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
		assertEquals(joel.getId(), results.getResources().iterator().next().get("id"));
	}

	@Test
	public void testFindIdsByUserNameContains() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName co 'd'", null, "ascending", 1,
				100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	@Ignore
	public void testFindIdsByNameExists() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "name pr", null, "ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
	}

	@Test
	public void testFindIdsByUserNameStartWith() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName sw 'j'", null, "ascending", 1,
				100);
		assertEquals(1, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsByEmailContains() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "emails.value sw 'j'", null,
				"ascending", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsByEmailContainsWithEmptyResult() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "emails.value sw 'z'", null,
				"ascending", 1, 100);
		assertEquals(0, results.getTotalResults());
	}

	@Test
	public void testFindIdsWithBooleanExpression() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName co 'd' and id pr", null,
				"ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsWithBooleanExpressionIvolvingEmails() {
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id",
				"userName co 'd' and emails.value co 'vmware'", null, "ascending", 1, 100);
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
