package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.extensions.profiles.DisabledIfProfile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

@DisabledIfProfile({"mysql", "postgresql"})
class HsqlDbMigrationIntegrationTest extends DbMigrationIntegrationTestParent {

    private final String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = UPPER(?) AND CONSTRAINT_NAME LIKE 'SYS_PK_%'";
    private final String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_SCHEMA = ? and TABLE_NAME != 'schema_version'";
    private final String insertNewOauthCodeRecord = "insert into oauth_code(code) values('code');";

    @Test
    void insertMissingPrimaryKeys_onMigrationOnNewDatabase() {
        MigrationTest migrationTest = new MigrationTest() {
            @Override
            public String getTargetMigration() {
                return "4.9.2";
            }

            @Override
            public void runAssertions() throws Exception {
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "OAUTH_CODE");
                assertThat(count).as("OAUTH_CODE is missing primary key").isOne();

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "GROUP_MEMBERSHIP");
                assertThat(count).as("GROUP_MEMBERSHIP is missing primary key").isOne();

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "SEC_AUDIT");
                assertThat(count).as("SEC_AUDIT is missing primary key").isOne();

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "EXTERNAL_GROUP_MAPPING");
                assertThat(count).as("EXTERNAL_GROUP_MAPPING is missing primary key").isOne();

                assertThatNoException().as("oauth_code table should auto increment primary key when inserting data.")
                        .isThrownBy(() -> jdbcTemplate.execute(insertNewOauthCodeRecord));
            }
        };

        migrationTestRunner.run(migrationTest);
    }

    @Test
    void everyTableShouldHaveAPrimaryKeyColumn() throws Exception {
        flyway.migrate();

        List<String> tableNames = jdbcTemplate.queryForList(getAllTableNames, String.class, getDatabaseCatalog());
        assertThat(tableNames).isNotEmpty();
        for (String tableName : tableNames) {
            int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), tableName);
            assertThat(count).as("%s is missing primary key".formatted(tableName)).isPositive();
        }
    }
}
