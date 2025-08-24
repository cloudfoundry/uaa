package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

import static org.assertj.core.api.Assertions.assertThat;

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
                foundTable = tableName.equalsIgnoreCase(rs.getString("TABLE_NAME"));
            }
            rs.close();
            assertThat(foundTable).as("Table " + tableName + " found!").isFalse();
        }
    }
}
