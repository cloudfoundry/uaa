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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Collection;

import static org.hamcrest.Matchers.isIn;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class ClientDetailsSupportsExtendedAuthoritesAndScopes extends JdbcTestBase {

    private String springProfile;
    private String tableName;
    private String columnNameOne;
    private String columnNameTwo;


    public ClientDetailsSupportsExtendedAuthoritesAndScopes(String springProfile, String tableName, String columnNameOne, String columnNameTwo) {
        this.springProfile = springProfile;
        this.tableName = tableName;
        this.columnNameOne = columnNameOne;
        this.columnNameTwo = columnNameTwo;
    }

    @Parameterized.Parameters(name = "{index}: org.cloudfoundry.identity.uaa.db[{0}]; table[{1}]")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {null, "oauth_client_details", "scope", "authorities"}
//            {"sqlserver", "oauth_client_details", "scope", "authorities"},
//            {"mysql", "oauth_client_details", "scope", "authorities"},
//            {"hsqldb", "oauth_client_details", "scope", "authorities"},
//            {"postgresql", "oauth_client_details", "scope", "authorities"}
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
    public void test_That_authorites_and_scopes_are_extended() throws Exception {
        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            boolean foundColumnScope = false;
            boolean foundColumnAutorities = false;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if (tableName.equalsIgnoreCase(rstableName) && (columnNameOne.equalsIgnoreCase(rscolumnName)
                        || columnNameTwo.equalsIgnoreCase(rscolumnName))) {
                    assertTrue("Table:"+rstableName+" Column:"+rscolumnName+" should be max in size.", columnSize > 4000);
                    foundTable = true;
                    if(columnNameOne.equalsIgnoreCase(rscolumnName)) {
                        foundColumnScope = true;
                    } else {
                        foundColumnAutorities = true;
                    }
                    String columnType = rs.getString("TYPE_NAME");
                    assertNotNull("Table:" + rstableName + " Column:" + rscolumnName + " should have a column type.", columnType);
                    assertThat("Table:" + rstableName + " Column:" + rscolumnName+" should be varchar", columnType.toLowerCase(), isIn(Arrays.asList("varchar","nvarchar","clob","text")));
                } else {
                    continue;
                }
            }
            rs.close();

            assertTrue("["+springProfile+"] I was expecting to find table:" + tableName, foundTable);
            assertTrue("["+springProfile+"] I was expecting to find column: "+columnNameOne, foundColumnScope);
            assertTrue("["+springProfile+"] I was expecting to find column: "+columnNameTwo, foundColumnAutorities);

        } finally {
            connection.close();
        }
    }
}