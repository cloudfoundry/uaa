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
package org.cloudfoundry.identity.uaa.password;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.scim.validate.NullPasswordValidator;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

public class PasswordChangeEndpointTests {

	private ScimUser joel;
	
	private ScimUser dale;

	private PasswordChangeEndpoint endpoints;

	private static EmbeddedDatabase database;

	@BeforeClass
	public static void init() {
		EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
		builder.addScript("classpath:/org/cloudfoundry/identity/uaa/schema-hsqldb.sql");
		builder.addScript("classpath:/org/cloudfoundry/identity/uaa/scim/schema-hsqldb.sql");
		database = builder.build();
	}
	
	@Before
	public void setup() {

		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		JdbcScimUserProvisioning dao = new JdbcScimUserProvisioning(jdbcTemplate);
		dao.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		dao.setPasswordValidator(new NullPasswordValidator());

		endpoints = new PasswordChangeEndpoint();
		endpoints.setScimUserProvisioning(dao);

		joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
		joel.addEmail("jdsa@vmware.com");
		dale = new ScimUser(null, "olds", "Dale", "Olds");
		dale.addEmail("olds@vmware.com");
		joel = dao.createUser(joel, "password");
		dale = dao.createUser(dale, "password");
		
	}

	@After
	public void clean() {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		if (joel!=null) {
			jdbcTemplate.update("delete from users where id=?", joel.getId());
		}
		if (dale!=null) {
			jdbcTemplate.update("delete from users where id=?", dale.getId());
		}
	}
	
	@AfterClass
	public static void tearDown() throws Exception {
		TestUtils.deleteFrom(database, "users", "groups", "group_membership");
		if (database != null) {
			database.shutdown();
		}
	}

	private SecurityContextAccessor mockSecurityContext(ScimUser user) {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		String id = user.getId();
		when(sca.getUserId()).thenReturn(id);
		return sca;
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

}
