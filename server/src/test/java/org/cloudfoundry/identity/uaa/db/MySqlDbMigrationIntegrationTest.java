package org.cloudfoundry.identity.uaa.db;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static java.lang.String.format;
import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;

public class MySqlDbMigrationIntegrationTest extends DbMigrationIntegrationTestParent {

    private String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'";
    private String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_SCHEMA = ?";
    private String insertNewOauthCodeRecord = "insert into oauth_code(code) values('code');";
    private String fetchColumnTypeFromTable = "SELECT column_type FROM information_schema.columns WHERE table_name = ? and TABLE_SCHEMA = ? and column_name = ?";
    private String fetchColumnIsNullableFromTable = "SELECT is_nullable FROM information_schema.columns WHERE table_name = ? and TABLE_SCHEMA = ? and column_name = ?";

    @Override
    protected String onlyRunTestsForActiveSpringProfileName() {
        return "mysql";
    }

    @Test
    public void insertMissingPrimaryKeys_onMigrationOnNewDatabase() {
        MigrationTest migrationTest = new MigrationTest() {
            @Override
            public String getTargetMigration() {
                return "4.9.2";
            }

            @Override
            public void runAssertions() throws Exception {
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "oauth_code");
                assertThat("oauth_code is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "group_membership");
                assertThat("group_membership is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "sec_audit");
                assertThat("sec_audit is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "external_group_mapping");
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
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "group_membership");
                assertThat("group_membership is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "external_group_mapping");
                assertThat("external_group_mapping is missing primary key", count, is(1));
            }
        });

        migrationTestRunner.run(migrationTest.toArray(new MigrationTest[]{}));
    }

    @Test
    public void everyTableShouldHaveAPrimaryKeyColumn() throws Exception {
        flyway.migrate();

        List<String> tableNames = jdbcTemplate.queryForList(getAllTableNames, String.class, jdbcTemplate.getDataSource().getConnection().getCatalog());
        assertThat(tableNames, hasSize(greaterThan(0)));
        for (String tableName : tableNames) {
            int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), tableName);
            assertThat(format("%s is missing primary key", tableName), count, greaterThanOrEqualTo(1));
        }
    }

    @Test
    public void mfaTableAddsTwoNewColumns() {
        MigrationTest migrationTest = new MigrationTest() {
            @Override
            public String getTargetMigration() {
                return "4.13.0";
            }

            @Override
            public void runAssertions() throws Exception {
                String keyColumnType = jdbcTemplate.queryForObject(
                  fetchColumnTypeFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getCatalog(),
                  "encryption_key_label"
                );
                assertThat(keyColumnType, is("varchar(255)"));

                String encryptedValidationCodeColumnType = jdbcTemplate.queryForObject(
                  fetchColumnTypeFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getCatalog(),
                  "encrypted_validation_code"
                );
                assertThat(encryptedValidationCodeColumnType, is("varchar(255)"));

                String encryptedVerificationCodeColumnIsNullable = jdbcTemplate.queryForObject(
                  fetchColumnIsNullableFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getCatalog(),
                  "encrypted_validation_code"
                );
                assertThat(encryptedVerificationCodeColumnIsNullable, is("YES"));

                String verificationCodeColumnIsNullable = jdbcTemplate.queryForObject(
                  fetchColumnIsNullableFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getCatalog(),
                  "validation_code"
                );
                assertThat(verificationCodeColumnIsNullable, is("YES"));

                String validationColumnType = jdbcTemplate.queryForObject(
                  fetchColumnTypeFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getCatalog(),
                  "validation_code"
                );
                assertThat(validationColumnType, is("int(11)"));

            }
        };

        migrationTestRunner.run(migrationTest);
    }
}
