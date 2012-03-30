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
