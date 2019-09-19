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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class ClientDetailsHasRequiredUserScopes extends JdbcTestBase {

    private String springProfile;
    private String tableName;
    private String columnName;

    public ClientDetailsHasRequiredUserScopes(String springProfile, String tableName, String columnName) {
        this.springProfile = springProfile;
        this.tableName = tableName;
        this.columnName = columnName;
    }

    @Parameterized.Parameters(name = "{index}: org.cloudfoundry.identity.uaa.db[{0}]; table[{1}]")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {null, "oauth_client_details", "required_user_groups"},
//            {"mysql", "oauth_client_details", "required_user_groups"},
//            {"hsqldb", "oauth_client_details", "required_user_groups"},
//            {"postgresql", "oauth_client_details", "required_user_groups"},
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
    public void test_That_required_user_groups_is_1024() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            boolean foundColumn = false;
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, null, null);
            while (rs.next()) {
                String rstableName = rs.getString("TABLE_NAME");
                String rscolumnName = rs.getString("COLUMN_NAME");
                int columnSize = rs.getInt("COLUMN_SIZE");
                if ((foundTable = tableName.equalsIgnoreCase(rstableName)) && columnName.equalsIgnoreCase(rscolumnName)) {
                    assertEquals("Table:" + rstableName + " Column:" + rscolumnName + " should be 1024 in size.", 1024, columnSize);
                    foundColumn = true;
                    String columnType = rs.getString("TYPE_NAME");
                    assertNotNull("Table:" + rstableName + " Column:" + rscolumnName + " should have a column type.", columnType);
                    assertThat("Table:" + rstableName + " Column:" + rscolumnName + " should be varchar", columnType.toLowerCase(), isIn(Arrays.asList("varchar", "nvarchar")));
                    break;
                }
            }
            rs.close();

            assertTrue("[" + springProfile + "] I was expecting to find table:" + tableName, foundTable);
            assertTrue("[" + springProfile + "] I was expecting to find column: " + columnName, foundColumn);
        }
    }
}
