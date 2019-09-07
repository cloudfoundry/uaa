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

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
public class ExpiringCodeTableTest extends JdbcTestBase {

    private String tableName = "expiring_code_store";


    private List<TestColumn> TEST_COLUMNS = Arrays.asList(
        new TestColumn("code", "varchar/nvarchar", 255),
        new TestColumn("expiresat", "bigint/int8", -1),
        new TestColumn("data", "longtext/mediumtext/nvarchar", -1),
        new TestColumn("intent", "longtext/mediumtext/nvarchar", -1),
        new TestColumn("identity_zone_id", "varchar/nvarchar", 36)
    );

    public boolean testColumn(String name, String type, int size) {
        return testColumn(TEST_COLUMNS, name, type, size);
    }
    public boolean testColumn(List<TestColumn> columns, String name, String type, int size) {
        for (TestColumn c : columns) {
            if (c.name.equalsIgnoreCase(name)) {
                return c.type.toLowerCase().contains(type.toLowerCase()) && c.size > 0 ? c.size == size : true;
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
                int actualColumnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName)) {
                    String actualColumnType = rs.getString("TYPE_NAME");
                    assertTrue("Testing column:"+rscolumnName, testColumn(rscolumnName, actualColumnType, actualColumnSize));
                    foundTable = true;
                    foundColumn++;
                }
            }
            rs.close();
            assertTrue("Table " + tableName + " not found!", foundTable);
            assertEquals("Table " + tableName + " is missing columns!", TEST_COLUMNS.size(), foundColumn);



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
