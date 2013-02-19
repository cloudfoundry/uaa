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
package org.cloudfoundry.identity.uaa.test;

import static org.junit.Assert.assertEquals;

import java.sql.Connection;

import javax.sql.DataSource;

import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.jdbc.datasource.init.ScriptStatementFailedException;
import org.springframework.util.ClassUtils;

/**
 * Common methods for DB manipulation and so on.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 * 
 */
public class TestUtils {

	private static Environment environment = TestProfileEnvironment.getEnvironment();

	private static String platform = environment.acceptsProfiles("postgresql") ? "postgresql" : "hsqldb";

	public static void runScript(DataSource dataSource, String stem) throws Exception {
		ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
		String packageName = ClassUtils.getPackageName(TestUtils.class).replace(".", "/");
		populator.addScript(new ClassPathResource(packageName.substring(0, packageName.lastIndexOf("/")) + "/" + stem
				+ "-" + platform + ".sql"));
		Connection connection = dataSource.getConnection();
		try {
			populator.populate(connection);
		}
		catch (ScriptStatementFailedException e) {
			// ignore
		}
		finally {
			DataSourceUtils.releaseConnection(connection, dataSource);
		}
	}

	public static void createSchema(DataSource dataSource) throws Exception {
		runScript(dataSource, "schema");
	}

	public static void dropSchema(DataSource dataSource) throws Exception {
		runScript(dataSource, "schema-drop");
	}

	public static void deleteFrom(DataSource dataSource, String... tables) throws Exception {
		for (String table : tables) {
			new JdbcTemplate(dataSource).update("delete from " + table);
		}
	}

	public static void assertNoSuchUser(JdbcTemplate template, String column, String value) {
		assertEquals(0, template.queryForInt("select count(id) from users where " + column + "='" + value + "'"));
	}

}
