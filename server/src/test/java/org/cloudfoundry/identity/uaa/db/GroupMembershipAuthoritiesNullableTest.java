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
import java.sql.SQLException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class GroupMembershipAuthoritiesNullableTest extends JdbcTestBase {

    @Test
    public void testAuthoritiesNullable() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            String profile = environment.getProperty("spring.profiles.active");
            ResultSet rs;
            rs = meta.getColumns(connection.getCatalog(), null, null, null);
            boolean call = false;
            while(rs.next()) {
                if("GROUP_MEMBERSHIP".equalsIgnoreCase(rs.getString("TABLE_NAME")) &&
                    "AUTHORITIES".equalsIgnoreCase(rs.getString("COLUMN_NAME"))) {
                    call = true;
                    assertEquals("YES", rs.getString("IS_NULLABLE").toUpperCase());
                }
            }
            assertTrue("authorities column not found.", call);
        }
    }

}
