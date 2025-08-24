package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.extensions.profiles.EnabledIfProfile;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

@EnabledIfProfile("mysql")
class MySqlDbMigrationIntegrationTest extends DbMigrationIntegrationTestParent {

    private final String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'";
    private final String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_SCHEMA = ?";
    private final String insertNewOauthCodeRecord = "insert into oauth_code(code) values('code');";

    @Test
    void insertMissingPrimaryKeys_onMigrationOnNewDatabase() {
        MigrationTest migrationTest = new MigrationTest() {
            @Override
            public String getTargetMigration() {
                return "4.9.2";
            }

            @Override
            public void runAssertions() {
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "oauth_code");
                assertThat(count).as("oauth_code is missing primary key").isOne();

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "group_membership");
                assertThat(count).as("group_membership is missing primary key").isOne();

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "sec_audit");
                assertThat(count).as("sec_audit is missing primary key").isOne();

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "external_group_mapping");
                assertThat(count).as("external_group_membership is missing primary key").isOne();

                assertThatNoException().as("oauth_code table should auto increment primary key when inserting data.")
                        .isThrownBy(() -> jdbcTemplate.execute(insertNewOauthCodeRecord));
            }
        };

        migrationTestRunner.run(migrationTest);
    }

    /*
        We have had to modify existing db migrations. This means that some uaa deploys will not apply these 'modified' migration scripts. We want to test that in these cases that primary key columns are still created
        See: https://www.pivotaltracker.com/story/show/155725419
    */
    @Test
    void insertMissingPrimaryKeys_whenOldMigrationWithoutPrimaryKeyModificationHasAlreadyRun() {
        List<MigrationTest> migrationTest = Arrays.asList(new MigrationTest() {
            // 2.4.1: removing the primary key column here would replicate the state before the migration was 'modified'.
            @Override
            public String getTargetMigration() {
                return "2.4.1";
            }

            @Override
            public void runAssertions() {
                jdbcTemplate.execute("ALTER TABLE group_membership drop column id");
                jdbcTemplate.execute("ALTER TABLE external_group_mapping drop column id");
            }
        }, new MigrationTest() {
            @Override
            public String getTargetMigration() {
                return "4.9.2";
            }

            @Override
            public void runAssertions() {
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "group_membership");
                assertThat(count).as("group_membership is missing primary key").isOne();

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "external_group_mapping");
                assertThat(count).as("external_group_mapping is missing primary key").isOne();
            }
        });

        migrationTestRunner.run(migrationTest.toArray(new MigrationTest[]{}));
    }

    @Test
    void everyTableShouldHaveAPrimaryKeyColumn() {
        flyway.migrate();

        List<String> tableNames = jdbcTemplate.queryForList(getAllTableNames, String.class, getDatabaseCatalog());
        assertThat(tableNames).isNotEmpty();
        for (String tableName : tableNames) {
            int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), tableName);
            assertThat(count).as("%s is missing primary key".formatted(tableName)).isPositive();
        }
    }
}
