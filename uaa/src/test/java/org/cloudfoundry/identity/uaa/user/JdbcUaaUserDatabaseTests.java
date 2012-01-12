/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
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
@IfProfileValue(name = "spring.profiles.active", values = { "" , "jdbc" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcUaaUserDatabaseTests {

	@Autowired
	private DataSource dataSource;

	private JdbcUaaUserDatabase db;

	private static final String JOE_ID = "550e8400-e29b-41d4-a716-446655440000";

	private static final String MABEL_ID = UUID.randomUUID().toString();

	@Before
	public void initializeDb() throws Exception {
		JdbcTemplate template = new JdbcTemplate(dataSource);
		db = new JdbcUaaUserDatabase(template);
		TestUtils.createSchema(dataSource);
		template.execute("insert into users (id, username, password, email, givenName, familyName) " + "values ('"
				+ JOE_ID + "', 'joe','joespassword','joe@joe.com','Joe','User')");
		template.execute("insert into users (id, username, password, email, givenName, familyName) " + "values ('"
				+ MABEL_ID + "', 'mabel','mabelspassword','mabel@mabel.com','Mabel','User')");
	}

	@After
	public void clearDb() throws Exception {
		TestUtils.dropSchema(dataSource);
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
