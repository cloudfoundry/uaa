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

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

import static org.junit.Assert.assertTrue;

public class TestSchemaValidation extends JdbcTestBase {

    @Test
    public void test_v2_3_6__That_Users_Perf_Id_Index_Exists() throws Exception {
        Connection connection = dataSource.getConnection();
        try {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundIndex = false;
            String[] tableNames = {"users", "USERS"};
            for (String tableName : tableNames) {
                ResultSet rs = meta.getIndexInfo(connection.getCatalog(), null, tableName, false, false);
                while ((!foundIndex) && rs.next()) {
                    String indexName = rs.getString("INDEX_NAME");
                    if ("user_perf_id".equalsIgnoreCase(indexName)) {
                        foundIndex = true;
                    }
                }
                rs.close();
                if (foundIndex) {
                    break;
                }
            }
            assertTrue("I was expecting to find index user_perf_id", foundIndex);
        } finally {
            connection.close();
        }


    }
}
