package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithDatabaseContext
class GroupMembershipAuthoritiesNullableTest {

    @Test
    void authoritiesNullable(@Autowired DataSource dataSource) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            ResultSet rs;
            rs = meta.getColumns(connection.getCatalog(), null, null, null);
            boolean call = false;
            while (rs.next()) {
                if ("GROUP_MEMBERSHIP".equalsIgnoreCase(rs.getString("TABLE_NAME")) &&
                        "AUTHORITIES".equalsIgnoreCase(rs.getString("COLUMN_NAME"))) {
                    call = true;
                    assertEquals("YES", rs.getString("IS_NULLABLE").toUpperCase());
                }
            }
            assertTrue(call, "authorities column not found.");
        }
    }

}
