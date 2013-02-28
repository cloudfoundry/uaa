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
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.UUID;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
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
@IfProfileValue(name = "spring.profiles.active", values = { "" , "hsqldb", "test,postgresql" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcUaaUserDatabaseTests {

	@Autowired
	private DataSource dataSource;

	private JdbcUaaUserDatabase db;

	private static final String JOE_ID = "550e8400-e29b-41d4-a716-446655440000";

	private static final String addUserSqlFormat = "insert into users (id, username, password, email, givenName, familyName, phoneNumber) values ('%s','%s','%s','%s','%s','%s','%s')";

	private static final String addGroupSqlFormat = "insert into groups (id, displayName) values ('%s','%s')";

	private static final String addMemberSqlFormat = "insert into group_membership (group_id, member_id, member_type, authorities) values ('%s', '%s', '%s', '%s')";

	private static final String MABEL_ID = UUID.randomUUID().toString();

	private JdbcTemplate template;

	private void addUser(String id, String name, String password) {
		TestUtils.assertNoSuchUser(template, "id", id);
		template.execute(String.format(addUserSqlFormat, id, name, password, name.toLowerCase() + "@test.org", name, name, ""));
	}

	private void addGroup(String id, String name) {
		TestUtils.assertNoSuchUser(template, "id", id);
		template.execute(String.format(addGroupSqlFormat, id, name));
	}

	private void addMember(String gId, String mId, String mType, String authorities) {
		template.execute(String.format(addMemberSqlFormat, gId, mId, mType, authorities));
	}

	@Before
	public void initializeDb() throws Exception {

		template = new JdbcTemplate(dataSource);

		db = new JdbcUaaUserDatabase(template);
		db.setDefaultAuthorities(Collections.singleton("uaa.user"));
		db.setUserAuthoritiesQuery("select g.displayName from groups g, group_membership m where g.id = m.group_id and m.member_id = ?");

		TestUtils.assertNoSuchUser(template, "id", JOE_ID);
		TestUtils.assertNoSuchUser(template, "id", MABEL_ID);
		TestUtils.assertNoSuchUser(template, "userName", "jo@foo.com");

		addUser(JOE_ID, "Joe", "joespassword");
		addUser(MABEL_ID, "mabel", "mabelspassword");

	}

	@After
	public void clearDb() throws Exception {
		TestUtils.deleteFrom(dataSource, "users", "groups", "group_membership");
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
		// only way to add to a user's authorities is by enrolling in corresponding groups
		addGroup("g2", "dash.admin");
		addMember("g2", JOE_ID, "USER", "READER");
		UaaUser joe = db.retrieveUserByName("joe");
		assertTrue("authorities does not contain uaa.user", joe.getAuthorities().contains(new SimpleGrantedAuthority("uaa.user")));
		assertTrue("authorities does not contain dash.admin", joe.getAuthorities().contains(new SimpleGrantedAuthority("dash.admin")));
	}
}
