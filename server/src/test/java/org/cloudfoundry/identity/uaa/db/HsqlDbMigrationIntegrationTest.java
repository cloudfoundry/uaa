package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.extensions.profiles.DisabledIfProfile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.fail;

@DisabledIfProfile({"mysql", "postgresql"})
public class HsqlDbMigrationIntegrationTest extends DbMigrationIntegrationTestParent {

    private final String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = UPPER(?) AND CONSTRAINT_NAME LIKE 'SYS_PK_%'";
    private final String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_SCHEMA = ? and TABLE_NAME != 'schema_version'";
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
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "OAUTH_CODE");
                assertThat("OAUTH_CODE is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "GROUP_MEMBERSHIP");
                assertThat("GROUP_MEMBERSHIP is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "SEC_AUDIT");
                assertThat("SEC_AUDIT is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, getDatabaseCatalog(), "EXTERNAL_GROUP_MAPPING");
                assertThat("EXTERNAL_GROUP_MAPPING is missing primary key", count, is(1));

                try {
                    jdbcTemplate.execute(insertNewOauthCodeRecord);
                } catch (Exception e) {
                    fail("oauth_code table should auto increment primary key when inserting data.");
                }
            }
        };

        migrationTestRunner.run(migrationTest);
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