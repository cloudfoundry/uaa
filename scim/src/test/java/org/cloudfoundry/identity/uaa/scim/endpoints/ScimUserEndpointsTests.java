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
package org.cloudfoundry.identity.uaa.scim.endpoints;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.internal.matchers.StringContains.containsString;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.rest.SearchResults;
import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.ScimSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.scim.validate.NullPasswordValidator;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
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
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpMediaTypeException;
import org.springframework.web.servlet.View;

/**
 * @author Dave Syer
 * @author Luke Taylor
 *
 */
public class ScimUserEndpointsTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private ScimUser joel;

	private ScimUser dale;

	private ScimUserEndpoints endpoints;

	private ScimGroupEndpoints groupEndpoints;

	private JdbcScimUserProvisioning dao;

	private JdbcScimGroupMembershipManager mm;

	private JdbcApprovalStore am;

	private static EmbeddedDatabase database;

	@BeforeClass
	public static void setUpDatabase() {
		EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
		builder.addScript("classpath:/org/cloudfoundry/identity/uaa/schema-hsqldb.sql");
		builder.addScript("classpath:/org/cloudfoundry/identity/uaa/scim/schema-hsqldb.sql");
		database = builder.build();		
	}

	@Before
	public void setUp() {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		dao = new JdbcScimUserProvisioning(jdbcTemplate);
		dao.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		dao.setPasswordValidator(new NullPasswordValidator());
		ScimSearchQueryConverter filterConverter = new ScimSearchQueryConverter();
		Map<String, String> replaceWith = new HashMap<String, String>();
		replaceWith.put("emails\\.value", "email");
		replaceWith.put("groups\\.display", "authorities");
		replaceWith.put("phoneNumbers\\.value", "phoneNumber");
		filterConverter.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
		dao.setQueryConverter(filterConverter);
		endpoints = new ScimUserEndpoints();
		endpoints.setScimUserProvisioning(dao);
		mm = new JdbcScimGroupMembershipManager(jdbcTemplate);
		mm.setScimUserProvisioning(dao);
		JdbcScimGroupProvisioning gdao = new JdbcScimGroupProvisioning(jdbcTemplate);
		mm.setScimGroupProvisioning(gdao);
		mm.setDefaultUserGroups(Collections.singleton("uaa.user"));
		endpoints.setScimGroupMembershipManager(mm);
		groupEndpoints = new ScimGroupEndpoints(gdao, mm);
		joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
		joel.addEmail("jdsa@vmware.com");
		dale = new ScimUser(null, "olds", "Dale", "Olds");
		dale.addEmail("olds@vmware.com");
		joel = dao.createUser(joel, "password");
		dale = dao.createUser(dale, "password");

		Map<Class<? extends Exception>, HttpStatus> map = new HashMap<Class<? extends Exception>, HttpStatus>();
		map.put(IllegalArgumentException.class, HttpStatus.BAD_REQUEST);
		map.put(UnsupportedOperationException.class, HttpStatus.BAD_REQUEST);
		map.put(BadSqlGrammarException.class, HttpStatus.BAD_REQUEST);
		map.put(DataIntegrityViolationException.class, HttpStatus.BAD_REQUEST);
		map.put(HttpMessageConversionException.class, HttpStatus.BAD_REQUEST);
		map.put(HttpMediaTypeException.class, HttpStatus.BAD_REQUEST);
		endpoints.setStatuses(map);

		am = new JdbcApprovalStore(jdbcTemplate, new ScimSearchQueryConverter());
		endpoints.setApprovalStore(am);
	}

	@AfterClass
	public static void tearDown() throws Exception {
		if (database != null) {
			database.shutdown();
		}
	}

	@After
	public void cleanUp() throws Exception {
		TestUtils.deleteFrom(database, "group_membership", "users", "groups");
	}

	private void validateUserGroups (ScimUser user, String... gnm) {
		Set<String> expectedAuthorities = new HashSet<String>();
		expectedAuthorities.addAll(Arrays.asList(gnm));
		expectedAuthorities.add("uaa.user");
		assertNotNull(user.getGroups());
		Log logger = LogFactory.getLog(getClass());
		logger.debug("user's groups: " + user.getGroups() + ", expecting: " + expectedAuthorities);
		assertEquals(expectedAuthorities.size(), user.getGroups().size());
		for (ScimUser.Group g : user.getGroups()) {
			assertTrue(expectedAuthorities.contains(g.getDisplay()));
		}
	}

	@Test
	public void groupsIsSyncedCorrectlyOnCreate() {
		ScimUser user = new ScimUser(null, "dave", "David", "Syer");
		user.addEmail("dsyer@vmware.com");
		user.setGroups(Arrays.asList(new ScimUser.Group(null, "test1")));
		ScimUser created = endpoints.createUser(user);
		validateUserGroups(created, "uaa.user");
	}

	@Test
	public void groupsIsSyncedCorrectlyOnUpdate() {
		ScimUser user = new ScimUser(null, "dave", "David", "Syer");
		user.addEmail("dsyer@vmware.com");
		ScimUser created = endpoints.createUser(user);
		validateUserGroups(created, "uaa.user");

		created.setGroups(Arrays.asList(new ScimUser.Group(null, "test1")));
		ScimUser updated = endpoints.updateUser(created, created.getId(), "*");
		validateUserGroups(updated, "uaa.user");
	}

	@Test
	public void groupsIsSyncedCorrectlyOnGet() {
		ScimUser user = new ScimUser(null, "dave", "David", "Syer");
		user.addEmail("dsyer@vmware.com");
		ScimUser created = endpoints.createUser(user);

		validateUserGroups(created, "uaa.user");

		ScimGroup g = new ScimGroup("test1");
		g.setMembers(Arrays.asList(new ScimGroupMember(created.getId())));
		g = groupEndpoints.createGroup(g);

		validateUserGroups(endpoints.getUser(created.getId()), "test1");
	}

	@Test
	public void approvalsIsSyncedCorrectlyOnCreate() {
		am.addApproval(new Approval("vidya", "c1", "s1", 6000, Approval.ApprovalStatus.APPROVED));
		ScimUser user = new ScimUser(null, "vidya", "Vidya", "V");
		user.addEmail("vidya@vmware.com");
		user.setApprovals(Collections.singleton(new Approval("vidya", "c1", "s1", 6000, Approval.ApprovalStatus.APPROVED)));
		ScimUser created = endpoints.createUser(user);

		assertNotNull(created.getApprovals());
		assertEquals(1, created.getApprovals().size());
	}

	@Test
	public void approvalsIsSyncedCorrectlyOnUpdate() {
		am.addApproval(new Approval("vidya", "c1", "s1", 6000, Approval.ApprovalStatus.APPROVED));
		am.addApproval(new Approval("vidya", "c1", "s2", 6000, Approval.ApprovalStatus.DENIED));

		ScimUser user = new ScimUser(null, "vidya", "Vidya", "V");
		user.addEmail("vidya@vmware.com");
		user.setApprovals(Collections.singleton(new Approval("vidya", "c1", "s1", 6000, Approval.ApprovalStatus.APPROVED)));
		ScimUser created = endpoints.createUser(user);
		assertNotNull(created.getApprovals());
		assertEquals(2, created.getApprovals().size());

		created.setApprovals(Collections.singleton(new Approval("vidya", "c1", "s1", 6000, Approval.ApprovalStatus.APPROVED)));
		ScimUser updated = endpoints.updateUser(created, created.getId(), "*");
		assertEquals(2, updated.getApprovals().size());
	}

	@Test
	public void approvalsIsSyncedCorrectlyOnGet() {
		assertEquals(0, endpoints.getUser(joel.getId()).getApprovals().size());

		am.addApproval(new Approval(joel.getUserName(), "c1", "s1", 6000, Approval.ApprovalStatus.APPROVED));
		am.addApproval(new Approval(joel.getUserName(), "c1", "s2", 6000, Approval.ApprovalStatus.DENIED));

		assertEquals(2, endpoints.getUser(joel.getId()).getApprovals().size());
	}

	@Test
	public void userGetsADefaultPassword() {
		ScimUser user = new ScimUser(null, "dave", "David", "Syer");
		user.addEmail("dsyer@vmware.com");
		ScimUser created = endpoints.createUser(user);
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
		try {
			endpoints.createUser(user);
			fail("Expected InvalidScimResourceException");
		}
		catch (InvalidScimResourceException e) {
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
		ScimUser created = endpoints.createUser(user);
		assertNull("A newly created user revealed its password", created.getPassword());
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		String password = jdbcTemplate.queryForObject("select password from users where id=?", String.class,
				created.getId());
		assertEquals("foo", password);
	}
	@Test
	public void deleteIsAllowedWithCorrectVersionInEtag() {
		ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
		exGuy.addEmail("exguy@imonlyheretobedeleted.com");
		exGuy = dao.createUser(exGuy, "exguyspassword");
		endpoints.deleteUser(exGuy.getId(), Integer.toString(exGuy.getMeta().getVersion()));
	}

	@Test
	public void deleteIsAllowedWithQuotedEtag() {
		ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
		exGuy.addEmail("exguy@imonlyheretobedeleted.com");
		exGuy = dao.createUser(exGuy, "exguyspassword");
		endpoints.deleteUser(exGuy.getId(), "\"*");
	}

	@Test(expected = OptimisticLockingFailureException.class)
	public void deleteIsNotAllowedWithWrongVersionInEtag() {
		ScimUser exGuy = new ScimUser(null, "deleteme2", "Expendable", "Guy");
		exGuy.addEmail("exguy2@imonlyheretobedeleted.com");
		exGuy = dao.createUser(exGuy, "exguyspassword");
		endpoints.deleteUser(exGuy.getId(), Integer.toString(exGuy.getMeta().getVersion() + 1));
	}

	@Test
	public void deleteIsAllowedWithNullEtag() {
		ScimUser exGuy = new ScimUser(null, "deleteme3", "Expendable", "Guy");
		exGuy.addEmail("exguy3@imonlyheretobedeleted.com");
		exGuy = dao.createUser(exGuy, "exguyspassword");
		endpoints.deleteUser(exGuy.getId(), null);
	}

	@Test
	public void deleteUserUpdatesGroupMembership() {
		ScimUser exGuy = new ScimUser(null, "deleteme3", "Expendable", "Guy");
		exGuy.addEmail("exguy3@imonlyheretobedeleted.com");
		exGuy = dao.createUser(exGuy, "exguyspassword");

		ScimGroup g = new ScimGroup("test1");
		g.setMembers(Arrays.asList(new ScimGroupMember(exGuy.getId())));
		g = groupEndpoints.createGroup(g);
		validateGroupMembers(g, exGuy.getId(), true);

		endpoints.deleteUser(exGuy.getId(), "*");
		validateGroupMembers(groupEndpoints.getGroup(g.getId()), exGuy.getId(), false);
	}

	private void validateGroupMembers(ScimGroup g, String mId, boolean expected) {
		boolean isMember = false;
		for (ScimGroupMember m : g.getMembers()) {
			if (mId.equals(m.getMemberId())) {
				isMember = true;
				break;
			}
		}
		assertEquals(expected, isMember);
	}

	@Test
	public void testFindAllIds() {
		SearchResults<?> results = endpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
	}

	@Test
	public void testFindPageOfIds() {
		SearchResults<?> results = endpoints.findUsers("id", "id pr", null, "ascending", 1, 1);
		assertEquals(2, results.getTotalResults());
		assertEquals(1, results.getResources().size());
	}

	@Test
	public void testFindMultiplePagesOfIds() {
		dao.setPageSize(1);
		SearchResults<?> results = endpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertEquals(2, results.getResources().size());
	}

	@Test
	public void testFindAllNames() {
		SearchResults<?> results = endpoints.findUsers("userName", "id pr", null, "ascending", 1, 100);
		Collection<Object> values = getSetFromMaps(results.getResources(), "userName");
		assertTrue(values.contains("olds"));
	}

	@Test
	public void testFindAllEmails() {
		SearchResults<?> results = endpoints.findUsers("emails.value", "id pr", null, "ascending", 1, 100);
		Collection<Object> values = getSetFromMaps(results.getResources(), "emails.value");
		assertTrue(values.contains(Arrays.asList("olds@vmware.com")));
	}

	@Test
	public void testInvalidFilterExpression() {
		expected.expect(ScimException.class);
		expected.expectMessage(containsString("Invalid filter"));
		SearchResults<?> results = endpoints.findUsers("id", "userName qq 'd'", null, "ascending", 1, 100);
		assertEquals(0, results.getTotalResults());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testFindIdsByUserName() {
		SearchResults<?> results = endpoints.findUsers("id", "userName eq 'jdsa'", null, "ascending", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
		assertEquals(joel.getId(), ((Map<String, Object>) results.getResources().iterator().next()).get("id"));
	}

	@Test
	public void testFindIdsByUserNameContains() {
		SearchResults<?> results = endpoints.findUsers("id", "userName co 'd'", null, "ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	@Ignore
	public void testFindIdsByNameExists() {
		SearchResults<?> results = endpoints.findUsers("id", "name pr", null, "ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
	}

	@Test
	public void testFindIdsByUserNameStartWith() {
		SearchResults<?> results = endpoints.findUsers("id", "userName sw 'j'", null, "ascending", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsByEmailContains() {
		SearchResults<?> results = endpoints.findUsers("id", "emails.value sw 'j'", null, "ascending", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsByEmailContainsWithEmptyResult() {
		SearchResults<?> results = endpoints.findUsers("id", "emails.value sw 'z'", null, "ascending", 1, 100);
		assertEquals(0, results.getTotalResults());
	}

	@Test
	public void testFindIdsWithBooleanExpression() {
		SearchResults<?> results = endpoints.findUsers("id", "userName co 'd' and id pr", null, "ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsWithBooleanExpressionIvolvingEmails() {
		SearchResults<?> results = endpoints.findUsers("id",
				"userName co 'd' and emails.value co 'vmware'", null, "ascending", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@SuppressWarnings("unchecked")
	private Collection<Object> getSetFromMaps(Collection<?> resources, String key) {
		Collection<Object> result = new ArrayList<Object>();
		for (Object map : resources) {
			result.add(((Map<String, Object>)map).get(key));
		}
		return result;
	}
}
