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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class TestThatClientIdIsVchar255 extends JdbcTestBase {

    private String springProfile;
    private String tableName;
    private String columnName;

    public TestThatClientIdIsVchar255(String springProfile, String tableName, String columnName) {
        this.springProfile = springProfile;
        this.tableName = tableName;
        this.columnName = columnName;
    }

    @Parameterized.Parameters(name = "{index}: org.cloudfoundry.identity.uaa.db[{0}]; table[{1}]")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {null, "authz_approvals", "client_id"},
            {null, "oauth_client_details", "client_id"},
            {null, "sec_audit", "principal_id"},
//            {"hsqldb", "authz_approvals", "client_id"},
//            {"hsqldb", "oauth_client_details", "client_id"},
//            {"hsqldb", "sec_audit", "principal_id"},
//            {"postgresql", "authz_approvals", "client_id"},
//            {"postgresql", "oauth_client_details", "client_id"},
//            {"postgresql", "sec_audit", "principal_id"},
//            {"mysql", "authz_approvals", "client_id"},
//            {"mysql", "oauth_client_details", "client_id"},
//            {"mysql", "sec_audit", "principal_id"},
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


    @Test
    public void test_That_ClientId_Is_Varchar_255() throws Exception {
        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            boolean foundColumn = false;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while ((!foundTable) && rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName) && columnName.equalsIgnoreCase(rscolumnName)) {

                    assertEquals("Table:"+rstableName+" Column:"+rscolumnName+" should be 255 in size.", 255, columnSize);
                    foundTable = true;
                    foundColumn = true;
                    String columnType = rs.getString("TYPE_NAME");
                    assertNotNull("Table:" + rstableName + " Column:" + rscolumnName + " should have a column type.", columnType);
                    assertEquals("Table:" + rstableName + " Column:" + rscolumnName+" should be varchar", "varchar", columnType.toLowerCase());

                }
            }
            rs.close();

            assertTrue("["+springProfile+"] I was expecting to find table:" + tableName, foundTable);
            assertTrue("["+springProfile+"] I was expecting to find column: client_id", foundColumn);

        } finally {
            connection.close();
        }


    }

}
