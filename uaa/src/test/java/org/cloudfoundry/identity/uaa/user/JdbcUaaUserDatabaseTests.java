/**
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

import java.util.UUID;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 * @author Dave Syer
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

	private static final String MABEL_ID = UUID.randomUUID().toString();

	private JdbcTemplate template;

	@Before
	public void initializeDb() throws Exception {

		template = new JdbcTemplate(dataSource);

		TestUtils.assertNoSuchUser(template, "id", JOE_ID);
		TestUtils.assertNoSuchUser(template, "id", MABEL_ID);
		TestUtils.assertNoSuchUser(template, "userName", "jo@foo.com");

		db = new JdbcUaaUserDatabase(template);
		TestUtils.createSchema(dataSource);
		template.execute("insert into users (id, username, password, email, givenName, familyName) " + "values ('"
				+ JOE_ID + "', 'joe','joespassword','joe@joe.com','Joe','User')");
		template.execute("insert into users (id, username, password, email, givenName, familyName) " + "values ('"
				+ MABEL_ID + "', 'mabel','mabelspassword','mabel@mabel.com','Mabel','User')");

	}

	@After
	public void clearDb() throws Exception {
		template.execute("delete from users where id = '" + JOE_ID + "'");
		template.execute("delete from users where id = '" + MABEL_ID + "'");
	}

	@Test
	public void getValidUserSucceeds() {
		UaaUser joe = db.retrieveUserByName("joe");
		assertNotNull(joe);
		assertEquals(JOE_ID, joe.getId());
		assertEquals("joe", joe.getUsername());
		assertEquals("joe@joe.com", joe.getEmail());
		assertEquals("joespassword", joe.getPassword());
	}

	@Test(expected = UsernameNotFoundException.class)
	public void getNonExistentUserRaisedNotFoundException() {
		db.retrieveUserByName("jo");
	}

}
