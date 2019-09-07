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
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

import static org.junit.Assert.assertFalse;
public class OldAuthzTableDropped extends JdbcTestBase {

    private String tableName = "authz_approvals_old";

    @Override
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        if (System.getProperty("spring.active.profiles")!=null) {
            environment.setActiveProfiles(System.getProperty("spring.active.profiles"));
        }
        setUp(environment);
    }

    @Test
    public void validate_table() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            ResultSet rs = meta.getTables(connection.getCatalog(), null, null, null);
            while (rs.next() && !foundTable) {
                foundTable = (tableName.equalsIgnoreCase(rs.getString("TABLE_NAME")));
            }
            rs.close();
            assertFalse("Table " + tableName + " found!", foundTable);
        }
    }
}
