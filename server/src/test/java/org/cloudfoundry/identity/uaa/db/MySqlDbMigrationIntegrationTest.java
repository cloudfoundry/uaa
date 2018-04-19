package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.lang.String.format;
import static java.lang.System.getProperties;
import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.junit.Assume.assumeTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:/spring/data-source.xml", "classpath*:/spring/env.xml"})
public class MySqlDbMigrationIntegrationTest {
    @Autowired
    private Flyway flyway;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'";
    private String getAllTableNames = "SELECT distinct TABLE_NAME from information_schema.KEY_COLUMN_USAGE where TABLE_SCHEMA = ?";
    private String insertNewOauthCodeRecord = "insert into oauth_code(code) values('code');";
    private String fetchColumnNameAndTypeFromTable = "SELECT column_name, column_type  FROM information_schema.columns WHERE table_name = 'user_google_mfa_credentials' and TABLE_SCHEMA = ? and column_name = ?";
    private MigrationTestRunner migrationTestRunner;

    @Before
    public void setup() {
        assumeTrue("Expected db profile to be enabled", getProperties().getProperty("spring.profiles.active").contains("mysql"));

        flyway.clean();
        migrationTestRunner = new MigrationTestRunner(flyway);
    }

    @After
    public void cleanup() {
        flyway.clean();
    }

    @Test
    public void insertMissingPrimaryKeys_onMigrationOnNewDatabase() throws SQLException {
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
                } catch (Exception _) {
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
    public void insertMissingPrimaryKeys_whenOldMigrationWithoutPrimaryKeyModificationHasAlreadyRun() throws SQLException {
        List<MigrationTest> migrationTest = Arrays.asList(new MigrationTest() {
            // 2.4.1: removing the primary key column here would replicate the state before the migration was 'modified'.
            @Override
            public String getTargetMigration() {
                return "2.4.1";
            }

            @Override
            public void runAssertions() throws Exception {
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
                Map<String, Object> mfaTableColumns = jdbcTemplate.queryForMap(
                  fetchColumnNameAndTypeFromTable,
                  jdbcTemplate.getDataSource().getConnection().getCatalog(),
                  "salt"
                );
                assertThat(mfaTableColumns, allOf(
                  hasEntry(is("column_name"), is("salt")),
                  hasEntry(is("column_type"), is("varchar(255)")))
                );

                mfaTableColumns = jdbcTemplate.queryForMap(
                  fetchColumnNameAndTypeFromTable,
                  jdbcTemplate.getDataSource().getConnection().getCatalog(),
                  "encryption_key_label"
                );
                assertThat(mfaTableColumns, allOf(
                  hasEntry(is("column_name"), is("encryption_key_label")),
                  hasEntry(is("column_type"), is("varchar(255)")))
                );
            }
        };

        migrationTestRunner.run(migrationTest);
    }
}