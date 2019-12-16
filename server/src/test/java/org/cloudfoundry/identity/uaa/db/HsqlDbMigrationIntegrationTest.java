package org.cloudfoundry.identity.uaa.db;

import org.junit.Test;

import java.util.List;

import static java.lang.String.format;
import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;

public class HsqlDbMigrationIntegrationTest extends DbMigrationIntegrationTestParent {

    private String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = UPPER(?) AND CONSTRAINT_NAME LIKE 'SYS_PK_%'";
    private String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_SCHEMA = ? and TABLE_NAME != 'schema_version'";
    private String insertNewOauthCodeRecord = "insert into oauth_code(code) values('code');";
    private String fetchColumnTypeFromTable = "SELECT DTD_IDENTIFIER FROM information_schema.columns WHERE table_name = ? and TABLE_SCHEMA = ? and column_name = ?";
    private String fetchColumnIsNullableFromTable = "SELECT IS_NULLABLE FROM information_schema.columns WHERE table_name = ? and TABLE_SCHEMA = ? and column_name = ?";

    @Override
    protected String onlyRunTestsForActiveSpringProfileName() {
        return "hsqldb";
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
                int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "OAUTH_CODE");
                assertThat("OAUTH_CODE is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "GROUP_MEMBERSHIP");
                assertThat("GROUP_MEMBERSHIP is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "SEC_AUDIT");
                assertThat("SEC_AUDIT is missing primary key", count, is(1));

                count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), "EXTERNAL_GROUP_MAPPING");
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
                String encryptedVerificationCodeColumnType = jdbcTemplate.queryForObject(
                  fetchColumnTypeFromTable,
                  String.class,
                  "USER_GOOGLE_MFA_CREDENTIALS",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "ENCRYPTED_VALIDATION_CODE"
                );
                assertThat(encryptedVerificationCodeColumnType, is("VARCHAR(255)"));

                String keyColumnType = jdbcTemplate.queryForObject(
                  fetchColumnTypeFromTable,
                  String.class,
                  "USER_GOOGLE_MFA_CREDENTIALS",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "ENCRYPTION_KEY_LABEL"
                );
                assertThat(keyColumnType, is("VARCHAR(255)"));

                String encryptedVerificationCodeColumnIsNullable = jdbcTemplate.queryForObject(
                  fetchColumnIsNullableFromTable,
                  String.class,
                  "USER_GOOGLE_MFA_CREDENTIALS",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "ENCRYPTED_VALIDATION_CODE"
                );
                assertThat(encryptedVerificationCodeColumnIsNullable, is("YES"));

                String verificationCodeColumnIsNullable = jdbcTemplate.queryForObject(
                  fetchColumnIsNullableFromTable,
                  String.class,
                  "USER_GOOGLE_MFA_CREDENTIALS",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "VALIDATION_CODE"
                );
                assertThat(verificationCodeColumnIsNullable, is("YES"));

                String verificationCodeColumnType = jdbcTemplate.queryForObject(
                  fetchColumnTypeFromTable,
                  String.class,
                  "USER_GOOGLE_MFA_CREDENTIALS",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "VALIDATION_CODE"
                );
                assertThat(verificationCodeColumnType, is("INTEGER"));
            }
        };

        migrationTestRunner.run(migrationTest);
    }
}