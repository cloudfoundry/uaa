package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

@WithDatabaseContext
class OldAuthzTableDropped {

    @Test
    void validate_table(@Autowired DataSource dataSource) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData meta = connection.getMetaData();
            boolean foundTable = false;
            ResultSet rs = meta.getTables(connection.getCatalog(), null, null, null);
            String tableName = "authz_approvals_old";
            while (rs.next() && !foundTable) {
                foundTable = (tableName.equalsIgnoreCase(rs.getString("TABLE_NAME")));
            }
            rs.close();
            assertFalse(foundTable, "Table " + tableName + " found!");
        }
    }
}
