/*
 * ****************************************************************************
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
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class UserInfoTableTest extends JdbcTestBase {

    private String tableName = "user_info";

    private List<TestColumn> TEST_COLUMNS = Arrays.asList(
        new TestColumn("user_id", "varchar", 36),
        new TestColumn("info", "longvarchar/mediumtext", 0)
    );


    @Override
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        if (System.getProperty("spring.active.profiles")!=null) {
            environment.setActiveProfiles(System.getProperty("spring.active.profiles"));
        }
        setUp(environment);
    }

    public boolean testColumn(String name, String type, int size) {
        return testColumn(TEST_COLUMNS, name, type, size);
    }
    public boolean testColumn(List<TestColumn> columns, String name, String type, int size) {
        for (TestColumn c : columns) {
            if (c.name.equalsIgnoreCase(name)) {
                return "varchar".equalsIgnoreCase(type) && !"info".equalsIgnoreCase(name) ?
                    c.type.toLowerCase().contains(type.toLowerCase()) && c.size == size :
                    c.type.toLowerCase().contains(type.toLowerCase());
            }
        }
        return false;
    }


    @Test
    public void validate_table() throws Exception {
        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            int foundColumn = 0;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName)) {
                    assertTrue("Testing column:"+rscolumnName, testColumn(rscolumnName, rs.getString("TYPE_NAME"), columnSize));
                    foundTable = true;
                    foundColumn++;
                }
            }
            rs.close();
            assertTrue("Table " + tableName + " not found!", foundTable);
            assertEquals("Table " + tableName + " is missing columns!", TEST_COLUMNS.size(), foundColumn);


            rs = meta.getIndexInfo(connection.getCatalog(), null, tableName, false, false);
            if (!rs.next()) {
                rs = meta.getIndexInfo(connection.getCatalog(), null, tableName.toUpperCase(), false, false);
                assertTrue(rs.next());
            }

        } finally{
            connection.close();
        }
    }

    public static class TestColumn {
        public final String name;
        public final String type;
        public final int size;

        public TestColumn(String name, String type, int size) {
            this.name = name;
            this.type = type;
            this.size = size;
        }
    }

}
