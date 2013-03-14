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
package org.cloudfoundry.identity.uaa.user;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.UUID;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 * @author Dave Syer
 * @author Vidya Valmikinathan
 */
@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "" , "hsqldb", "test,postgresql", "test,mysql" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcUaaUserDatabaseTests {

	@Autowired
	private DataSource dataSource;

	private JdbcUaaUserDatabase db;

	private static final String JOE_ID = "550e8400-e29b-41d4-a716-446655440000";

	private static final String addUserSql = "insert into users (id, username, password, email, givenName, familyName, phoneNumber) values (?,?,?,?,?,?,?)";

	private static final String getAuthoritiesSql = "select authorities from users where id=?";

	private static final String addAuthoritySql = "update users set authorities=? where id=?";

	private static final String MABEL_ID = UUID.randomUUID().toString();

	private JdbcTemplate template;

	private void addUser(String id, String name, String password) {
		TestUtils.assertNoSuchUser(template, "id", id);
		template.update(addUserSql, id, name, password, name.toLowerCase() + "@test.org", name, name, "");
	}

	private void addAuthority(String authority, String userId) {
		String authorities = template.queryForObject(getAuthoritiesSql, String.class, userId);
		authorities = authorities==null ? authority : authorities + "," + authority;
		template.update(addAuthoritySql, authorities, userId);
	}

	@Before
	public void initializeDb() throws Exception {

		template = new JdbcTemplate(dataSource);

		db = new JdbcUaaUserDatabase(template);
		db.setDefaultAuthorities(Collections.singleton("uaa.user"));

		TestUtils.assertNoSuchUser(template, "id", JOE_ID);
		TestUtils.assertNoSuchUser(template, "id", MABEL_ID);
		TestUtils.assertNoSuchUser(template, "userName", "jo@foo.com");

		addUser(JOE_ID, "Joe", "joespassword");
		addUser(MABEL_ID, "mabel", "mabelspassword");

	}

	@After
	public void clearDb() throws Exception {
		TestUtils.deleteFrom(dataSource, "users");
	}

	@Test
	public void getValidUserSucceeds() {
		UaaUser joe = db.retrieveUserByName("joe");
		assertNotNull(joe);
		assertEquals(JOE_ID, joe.getId());
		assertEquals("Joe", joe.getUsername());
		assertEquals("joe@test.org", joe.getEmail());
		assertEquals("joespassword", joe.getPassword());
		assertTrue("authorities does not contain uaa.user", joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
	}

	@Test
	public void getValidUserCaseInsensitive() {
		UaaUser joe = db.retrieveUserByName("JOE");
		assertNotNull(joe);
		assertEquals(JOE_ID, joe.getId());
		assertEquals("Joe", joe.getUsername());
		assertEquals("joe@test.org", joe.getEmail());
		assertEquals("joespassword", joe.getPassword());
		assertTrue("authorities does not contain uaa.user", joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
	}

	@Test(expected = UsernameNotFoundException.class)
	public void getNonExistentUserRaisedNotFoundException() {
		db.retrieveUserByName("jo");
	}

	@Test
	public void getUserWithExtraAuthorities() {
		addAuthority("dash.admin", JOE_ID);
		UaaUser joe = db.retrieveUserByName("joe");
		assertTrue("authorities does not contain uaa.user", joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
		assertTrue("authorities does not contain dash.admin", joe.getAuthorities().contains(new SimpleGrantedAuthority("dash.admin")));
	}
}
