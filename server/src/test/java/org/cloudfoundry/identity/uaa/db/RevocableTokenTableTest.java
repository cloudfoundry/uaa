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

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;
import org.junit.runners.Parameterized;
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

//@RunWith(Parameterized.class)
public class RevocableTokenTableTest extends JdbcTestBase {

    private String springProfile;
    private String tableName = "revocable_tokens";

    private List<TestColumn> TEST_COLUMNS = Arrays.asList(
        new TestColumn("token_id", "varchar", 36),
        new TestColumn("client_id", "varchar", 255),
        new TestColumn("user_id", "varchar", 36),
        new TestColumn("format", "varchar", 255),
        new TestColumn("response_type", "varchar", 25),
        new TestColumn("issued_at", "bigint/int8", 64),
        new TestColumn("expires_at", "bigint/int8", 64),
        new TestColumn("scope", "varchar", 1000),
        new TestColumn("data", "longvarchar/mediumtext", 0),
        new TestColumn("identity_zone_id", "varchar", 36)
    );

    private List<TestColumn> TEST_INDEX = Arrays.asList(
        new TestColumn("idx_revocable_token_client_id", "", 0),
        new TestColumn("idx_revocable_token_user_id", "", 0),
        new TestColumn("idx_revocable_token_expires_at", "", 0)

    );

//    public RevocableTokenTableTest(String springProfile, String tableName) {
//        this.springProfile = springProfile;
//        this.tableName = tableName;
//    }

    @Parameterized.Parameters(name = "{index}: org.cloudfoundry.identity.uaa.db[{0}]; table[{1}]")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {"hsqldb", "revocable_tokens"},
            {"postgresql", "revocable_tokens"},
            {"mysql", "revocable_tokens"}
        });
    }

    @Override
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        if ( springProfile!=null ) {
            environment.setActiveProfiles(springProfile);
        }
        setUp(environment);
    }

    public boolean testColumn(String name, String type, int size) {
        return testColumn(TEST_COLUMNS, name, type, size);
    }
    public boolean testColumn(List<TestColumn> columns, String name, String type, int size) {
        for (TestColumn c : columns) {
            if (c.name.equalsIgnoreCase(name)) {
                return "varchar".equalsIgnoreCase(type) && !"data".equalsIgnoreCase(name) ?
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
            int indexCount = 0;
            do {
                String indexName = rs.getString("INDEX_NAME");
                Short indexType = rs.getShort("TYPE");
                if (shouldCompareIndex(indexName)) {
                    assertTrue("Testing index: "+ indexName, testColumn(TEST_INDEX, indexName, "", indexType));
                    indexCount++;

                }
            } while (rs.next());
            assertEquals("One or more indices are missing", TEST_INDEX.size(), indexCount);
        } finally{
            connection.close();
        }
    }

    public boolean shouldCompareIndex(String indexName) {
        for (TestColumn c : TEST_INDEX) {
            if (c.name.equalsIgnoreCase(indexName)) {
                return true;
            }
        }
        return false;
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
