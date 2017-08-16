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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class GroupMembershipAuthoritiesNullableTest extends JdbcTestBase {

    @Test
    public void testAuthoritiesNullable() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            ResultSet rs = meta.getColumns(connection.getCatalog(), null, "GROUP_MEMBERSHIP", "AUTHORITIES");
            assertTrue(rs.next());
            assertEquals("GROUP_MEMBERSHIP", rs.getString("TABLE_NAME").toUpperCase());
            assertEquals("AUTHORITIES", rs.getString("COLUMN_NAME").toUpperCase());
            assertEquals("YES", rs.getString("IS_NULLABLE").toUpperCase());
            assertFalse(rs.next());
        }
    }

}
