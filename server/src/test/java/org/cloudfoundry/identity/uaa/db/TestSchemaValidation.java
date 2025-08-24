package org.cloudfoundry.identity.uaa.db;

import org.apache.commons.lang3.ArrayUtils;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
public class TestSchemaValidation {

    @Autowired
    private Environment environment;

    @Autowired
    private DataSource dataSource;

    @Test
    void v2_3_6_that_users_perf_id_index_exists() throws Exception {
        String[] tableNames = {"users", "USERS"};
        validate_index_existence(tableNames, "user_perf_id");
    }

    @Test
    void v3_9_0_that_group_membership_perf_id_index_exists() throws Exception {
        String tableName = "group_membership";
        validate_index_existence(new String[]{tableName, tableName.toUpperCase()}, "group_membership_perf_idx");
    }

    @Test
    void v4_6_0_that_group_membership_perf_id_index_exists() throws Exception {
        String tableName = "group_membership";
        validate_index_existence(new String[]{tableName, tableName.toUpperCase()}, "group_membership_perf_group_idx");
        if (ArrayUtils.contains(environment.getActiveProfiles(), "postgresql")) {
            validate_index_existence(new String[]{tableName, tableName.toUpperCase()}, "group_membership_perf_group_lower_idx");
        }
    }

    public void validate_index_existence(String[] tableNames, String lookupIndexName) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
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
            assertThat(foundIndex).as("I was expecting to find index " + lookupIndexName).isTrue();
        }
    }
}
