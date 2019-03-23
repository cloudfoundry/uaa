/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TableAndColumnNormalizationTest extends JdbcTestBase {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Before
    public void checkMysqlOrPostgresqlProfile() {
        Assume.assumeTrue(
            Arrays.asList(webApplicationContext.getEnvironment().getActiveProfiles()).contains("mysql") ||
            Arrays.asList(webApplicationContext.getEnvironment().getActiveProfiles()).contains("postgresql")
        );
    }

    @Override
    public String[] getWebApplicationContextConfigFiles() {
        return new String[]{
                "classpath:spring/env.xml",
                "classpath:spring/use_uaa_db_in_mysql_url.xml", // adds this one
                "classpath:spring/data-source.xml"
        };
    }

    @Test
    public void checkTables() throws Exception {
        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet rs = metaData.getTables(null, null, null, new String[] { "TABLE" });
            int count = 0;
            while (rs.next()) {
                String name = rs.getString("TABLE_NAME");
                logger.info("Checking table [" + name + "]");
                if (name != null && DatabaseInformation1_5_3.tableNames.contains(name.toLowerCase())) {
                    count++;
                    logger.info("Validating table [" + name + "]");
                    assertTrue("Table[" + name + "] is not lower case.", name.toLowerCase().equals(name));
                }
            }
            assertEquals("Table count:", DatabaseInformation1_5_3.tableNames.size(), count);

        } finally {
            try {
                connection.close();
            } catch (Exception ignore) {
            }
        }
    }

    @Test
    public void checkColumns() throws Exception {
        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData metaData = connection.getMetaData();
            ResultSet rs = metaData.getColumns(null, null, null, null);
            boolean hadSomeResults = false;
            while (rs.next()) {
                hadSomeResults = true;
                String name = rs.getString("TABLE_NAME");
                String col = rs.getString("COLUMN_NAME");
                logger.info("Checking column [" + name + "." + col + "]");
                if (name != null && DatabaseInformation1_5_3.tableNames.contains(name.toLowerCase())) {
                    logger.info("Validating column [" + name + "." + col + "]");
                    assertTrue("Column[" + name + "." + col + "] is not lower case.", col.toLowerCase().equals(col));
                }
            }
            assertTrue("Getting columns from db metadata should have returned some results", hadSomeResults);
        } finally {
            try {
                connection.close();
            } catch (Exception ignore) {
            }
        }
    }
}
