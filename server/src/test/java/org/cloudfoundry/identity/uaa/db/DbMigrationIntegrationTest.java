package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

@Profile("mysql")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath*:/spring/data-source.xml", "classpath*:/spring/env.xml"})
public class DbMigrationIntegrationTest {
    @Autowired
    private Flyway flyway;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'";
    private MigrationTestRunner migrationTestRunner;

    @Before
    public void setup() {
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
}