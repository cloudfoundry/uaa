/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.db;

import static org.hamcrest.Matchers.isIn;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.StringUtils;

public class ClientDetailsSupportsExtendedAuthoritesAndScopes extends JdbcTestBase {

    private String tableName = "oauth_client_details";
    private String scopeColumnName = "scope";
    private String authoritiesColumnName = "authorities";

    @Override
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        if (System.getProperty("spring.profiles.active")!=null) {
            environment.setActiveProfiles(StringUtils.commaDelimitedListToStringArray(System.getProperty("spring.profiles.active")));
        }
        setUp(environment);
    }

    @Test
    public void test_That_authorites_and_scopes_are_extended() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            boolean foundColumnScope = false;
            boolean foundColumnAuthorities = false;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName) && (scopeColumnName.equalsIgnoreCase(rscolumnName)
                        || authoritiesColumnName.equalsIgnoreCase(rscolumnName))) {
                    assertTrue(String.format("Table: %s Column: %s should be over 4000 chars", rstableName, rscolumnName), columnSize > 4000);
                    foundTable = true;
                    if (scopeColumnName.equalsIgnoreCase(rscolumnName)) {
                        foundColumnScope = true;
                    } else if (authoritiesColumnName.equalsIgnoreCase(rscolumnName)) {
                        foundColumnAuthorities = true;
                    }

                    String columnType = rs.getString("TYPE_NAME");
                    assertNotNull(String.format("Table: %s Column: %s should have a column type", rstableName, rscolumnName), columnType);
                    assertThat(String.format("Table: %s Column: %s should be text, longtext, nvarchar or clob", rstableName, rscolumnName), columnType.toLowerCase(), isIn(Arrays.asList("text", "longtext", "nvarchar", "clob")));
                }
            }
            rs.close();

            assertTrue("I was expecting to find table:" + tableName, foundTable);
            assertTrue("I was expecting to find column: " + scopeColumnName, foundColumnScope);
            assertTrue("I was expecting to find column: " + authoritiesColumnName, foundColumnAuthorities);
        }
    }
}
