package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
class RevocableTokenIndexTest_4_0_8 {

    private String tableName;
    private String indexName;
    private boolean unique;

    RevocableTokenIndexTest_4_0_8() {
        this.tableName = "revocable_tokens";
        this.indexName = "revocable_tokens_zone_id";
        this.unique = false;
    }

    @Test
    void existingIndices(@Autowired DataSource dataSource) throws Exception {
        boolean found = false;
        for (String tableName : Arrays.asList(tableName.toLowerCase(), tableName.toUpperCase())) {
            try (
                    Connection connection = dataSource.getConnection();
                    ResultSet rs = connection.getMetaData().getIndexInfo(connection.getCatalog(), null, tableName, unique, true)
            ) {
                while (!found && rs.next()) {
                    found = indexName.equalsIgnoreCase(rs.getString("INDEX_NAME"));
                }
            }
            if (found) {
                break;
            }
        }

        assertThat(found).as("Expected to find index %s.%s".formatted(tableName, indexName)).isTrue();
    }

}
