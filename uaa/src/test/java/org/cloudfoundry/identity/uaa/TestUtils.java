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
package org.cloudfoundry.identity.uaa;

import java.sql.Connection;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.scim.JdbcScimUserProvisioning;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.jdbc.datasource.init.ScriptStatementFailedException;

/**
 * Common methods for DB manipulation and so on.
 *
 * @author Luke Taylor
 */
public class TestUtils {
	private static String platform = System.getProperty("PLATFORM", "hsqldb");

	public static void runScript(DataSource dataSource, String stem) throws Exception {
		ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
		populator.addScript(new ClassPathResource("/org/cloudfoundry/identity/uaa/" + stem + "-" + platform + ".sql", TestUtils.class));
		Connection connection = dataSource.getConnection();
		try {
			populator.populate(connection);
		} catch (ScriptStatementFailedException e) {
			// ignore
		} finally {
			DataSourceUtils.releaseConnection(connection, dataSource);
		}
	}

	public static void createSchema(DataSource dataSource) throws Exception {
		runScript(dataSource, "schema");
	}

	public static void dropSchema(DataSource dataSource) throws Exception {
		runScript(dataSource, "schema-drop");
	}

}
