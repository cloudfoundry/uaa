/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.db;

import org.apache.commons.lang.ArrayUtils;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

import static org.junit.Assert.assertTrue;

public class TestSchemaValidation extends JdbcTestBase {

    @Test
    public void test_v2_3_6__That_Users_Perf_Id_Index_Exists() throws Exception {
        String[] tableNames = {"users", "USERS"};
        validate_index_existence(tableNames, "user_perf_id");
    }

    @Test
    public void test_v3_9_0__That_Group_Membership_Perf_Id_Index_Exists() throws Exception {
        String tableName = "group_membership";
        validate_index_existence(new String[] {tableName,tableName.toUpperCase()}, "group_membership_perf_idx");
    }

    @Test
    public void test_v4_6_0__That_Group_Membership_Perf_Id_Index_Exists() throws Exception {
        String tableName = "group_membership";
        validate_index_existence(new String[] {tableName,tableName.toUpperCase()}, "group_membership_perf_group_idx");
        if (ArrayUtils.contains(environment.getActiveProfiles(), "postgresql")) {
            validate_index_existence(new String[] {tableName,tableName.toUpperCase()}, "group_membership_perf_group_lower_idx");
        }
    }


    public void validate_index_existence(String[] tableNames, String lookupIndexName) throws Exception {

        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundIndex = false;
            for (String tableName : tableNames) {
                ResultSet rs = meta.getIndexInfo(connection.getCatalog(), null, tableName, false, false);
                while ((!foundIndex) && rs.next()) {
                    String indexName = rs.getString("INDEX_NAME");
                    if (lookupIndexName.equalsIgnoreCase(indexName)) {
                        foundIndex = true;
                    }
                }
                rs.close();
                if (foundIndex) {
                    break;
                }
            }
            assertTrue("I was expecting to find index "+ lookupIndexName, foundIndex);
        } finally {
            connection.close();
        }
    }
}
