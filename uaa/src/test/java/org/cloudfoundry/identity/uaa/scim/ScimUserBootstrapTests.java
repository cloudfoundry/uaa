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
package org.cloudfoundry.identity.uaa.scim;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collection;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class ScimUserBootstrapTests {

	private JdbcScimUserProvisioning db;

	private EmbeddedDatabase database;

	@Before
	public void setUp() {
		EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
		builder.addScript("classpath:/org/cloudfoundry/identity/uaa/schema-hsqldb.sql");
		database = builder.build();
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		db = new JdbcScimUserProvisioning(jdbcTemplate);
		db.setPasswordValidator(new NullPasswordValidator());
	}

	@After
	public void shutdownDb() throws Exception {
		database.shutdown();
	}

	@Test
	public void canAddUsers() throws Exception {
		UaaUser joe = new UaaUser("joe", "password", "joe@test.org", "Joe", "User");
		UaaUser mabel = new UaaUser("mabel", "password", "mabel@blah.com", "Mabel", "User");
		ScimUserBootstrap bootstrap = new ScimUserBootstrap(db, Arrays.asList(joe, mabel));
		bootstrap.afterPropertiesSet();
		Collection<ScimUser> users = db.retrieveUsers();
		assertEquals(2, users.size());
	}

}
