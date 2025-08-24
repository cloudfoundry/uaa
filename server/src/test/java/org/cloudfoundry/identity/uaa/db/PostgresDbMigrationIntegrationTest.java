package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.extensions.profiles.EnabledIfProfile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

@EnabledIfProfile("postgresql")
class PostgresDbMigrationIntegrationTest extends DbMigrationIntegrationTestParent {

    private final String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_CATALOG = ? AND TABLE_NAME = LOWER(?) AND CONSTRAINT_NAME LIKE LOWER(?)";
    private final String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_CATALOG = ? and TABLE_NAME != 'schema_version' AND TABLE_SCHEMA != 'pg_catalog'";
    private final String insertNewOauthCodeRecord = "insert into oauth_code(code) values('code');";

    @Test
    void everyTableShouldHaveAPrimaryKeyColumn() throws Exception {
        flyway.migrate();

        List<String> tableNames = jdbcTemplate.queryForList(getAllTableNames, String.class, getDatabaseCatalog());
        assertThat(tableNames).isNotEmpty();
        for (String tableName : tableNames) {
            int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), tableName, "%" + tableName + "_pk%");
            assertThat(count).as("%s is missing primary key".formatted(tableName)).isPositive();
        }

        assertThatNoException().as("oauth_code table should auto increment primary key when inserting data.")
                .isThrownBy(() -> jdbcTemplate.execute(insertNewOauthCodeRecord));
    }
}
