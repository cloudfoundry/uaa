package org.cloudfoundry.identity.uaa.db;

import org.junit.Test;

import java.util.List;

import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.fail;

public class PostgresDbMigrationIntegrationTest extends DbMigrationIntegrationTestParent {

    private String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_CATALOG = ? AND TABLE_NAME = LOWER(?) AND CONSTRAINT_NAME LIKE LOWER(?)";
    private String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_CATALOG = ? and TABLE_NAME != 'schema_version'";
    private String insertNewOauthCodeRecord = "insert into oauth_code(code) values('code');";
    private String fetchColumnTypeFromTable = "SELECT udt_name FROM information_schema.columns WHERE table_name = ? and TABLE_SCHEMA = ? and column_name = ?";
    private String fetchIsNullableFromTable = "SELECT is_nullable FROM information_schema.columns WHERE table_name = ? and TABLE_SCHEMA = ? and column_name = ?";

    @Override
    protected String onlyRunTestsForActiveSpringProfileName() {
        return "postgresql";
    }

    @Test
    public void everyTableShouldHaveAPrimaryKeyColumn() throws Exception {
        flyway.migrate();

        List<String> tableNames = jdbcTemplate.queryForList(getAllTableNames, String.class, jdbcTemplate.getDataSource().getConnection().getCatalog());
        assertThat(tableNames, hasSize(greaterThan(0)));
        for (String tableName : tableNames) {
            int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), tableName, "%" + tableName + "_pk%");
            assertThat(format("%s is missing primary key", tableName), count, greaterThanOrEqualTo(1));
        }

        try {
            jdbcTemplate.execute(insertNewOauthCodeRecord);
        } catch (Exception e) {
            fail("oauth_code table should auto increment primary key when inserting data.");
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
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "encryption_key_label"
                );
                assertThat(keyColumnType, is("varchar"));

                String encryptedValidationCodeColumnType = jdbcTemplate.queryForObject(
                  fetchColumnTypeFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "encrypted_validation_code"
                );
                assertThat(encryptedValidationCodeColumnType, is("varchar"));

                String encryptedValidationCodeIsNullable = jdbcTemplate.queryForObject(
                  fetchIsNullableFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "encrypted_validation_code"
                );
                assertThat(encryptedValidationCodeIsNullable, is("YES"));

                String validationCodeIsNullable = jdbcTemplate.queryForObject(
                  fetchIsNullableFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "validation_code"
                );
                assertThat(validationCodeIsNullable, is("YES"));

                String validationColumnType = jdbcTemplate.queryForObject(
                  fetchColumnTypeFromTable,
                  String.class,
                  "user_google_mfa_credentials",
                  jdbcTemplate.getDataSource().getConnection().getSchema(),
                  "validation_code"
                );
                assertThat(validationColumnType, is("int4"));
            }
        };

        migrationTestRunner.run(migrationTest);
    }
}