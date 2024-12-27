package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.extensions.profiles.EnabledIfProfile;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.fail;

@EnabledIfProfile("mysql")
public class MySqlDbMigrationIntegrationTest extends DbMigrationIntegrationTestParent {

    private final String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'";
    private final String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_SCHEMA = ?";
    private final String insertNewOauthCodeRecord = "insert into oauth_code(code) values('code');";

    @Test
    public void insertMissingPrimaryKeys_onMigrationOnNewDatabase() {
        MigrationTest migrationTest = new MigrationTest() {
            @Override
            public String getTargetMigration() {
                return "4.9.2";
            }

            @Override
            public void runAssertions() throws Exception {
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "oauth_code");
                assertThat("oauth_code is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "group_membership");
                assertThat("group_membership is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "sec_audit");
                assertThat("sec_audit is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "external_group_mapping");
                assertThat("external_group_membership is missing primary key", count, is(1));

                try {
                    jdbcTemplate.execute(insertNewOauthCodeRecord);
                } catch (Exception e) {
                    fail("oauth_code table should auto increment primary key when inserting data.");
                }
            }
        };

        migrationTestRunner.run(migrationTest);
    }

    /*
        We have had to modify existing db migrations. This means that some uaa deploys will not apply these 'modified' migration scripts. We want to test that in these cases that primary key columns are still created
        See: https://www.pivotaltracker.com/story/show/155725419
    */
    @Test
    public void insertMissingPrimaryKeys_whenOldMigrationWithoutPrimaryKeyModificationHasAlreadyRun() {
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
            public void runAssertions() throws Exception {
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "group_membership");
                assertThat("group_membership is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "external_group_mapping");
                assertThat("external_group_mapping is missing primary key", count, is(1));
            }
        });

        migrationTestRunner.run(migrationTest.toArray(new MigrationTest[]{}));
    }

    @Test
    public void everyTableShouldHaveAPrimaryKeyColumn() throws Exception {
        flyway.migrate();

        List<String> tableNames = jdbcTemplate.queryForList(getAllTableNames, String.class, getDatabaseCatalog());
        assertThat(tableNames, hasSize(greaterThan(0)));
        for (String tableName : tableNames) {
            int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), tableName);
            assertThat("%s is missing primary key".formatted(tableName), count, greaterThanOrEqualTo(1));
        }
    }
}
