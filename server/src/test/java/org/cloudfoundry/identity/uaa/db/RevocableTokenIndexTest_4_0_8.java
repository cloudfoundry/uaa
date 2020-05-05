package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.ResultSet;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class RevocableTokenIndexTest_4_0_8 extends JdbcTestBase {

    private String springProfile;
    private String tableName;
    private String indexName;
    private boolean unique;

    public RevocableTokenIndexTest_4_0_8() {
        this.springProfile = null;
        this.tableName = "revocable_tokens";
        this.indexName = "revocable_tokens_zone_id";
        this.unique = false;
    }

    @Override
    public void setUp() {
        MockEnvironment environment = new MockEnvironment();
        if (springProfile != null) {
            environment.setActiveProfiles(springProfile);
        }
        setUp(environment);
    }

    @Test
    public void existingIndices() throws Exception {
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

        assertTrue(String.format("Expected to find index %s.%s", tableName, indexName), found);
    }

}
