package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.sql.SQLException;


@ExtendWith(SpringExtension.class)
@ContextConfiguration(locations = {
        "classpath:spring/env.xml",
        "classpath:spring/jdbc-test-base-add-flyway.xml",
        "classpath:spring/data-source.xml",
})
public abstract class DbMigrationIntegrationTestParent {

    @Autowired
    protected Flyway flyway;
    @Autowired
    protected JdbcTemplate jdbcTemplate;

    MigrationTestRunner migrationTestRunner;
    private boolean dbNeedsResetting;

    @BeforeEach
    public void setup() {
        dbNeedsResetting = true;
        flyway.clean();
        migrationTestRunner = new MigrationTestRunner(flyway);
    }

    @AfterEach
    public void cleanup() throws SQLException {
        if (dbNeedsResetting) { // cleanup() is always called, even when setup()'s assumeTrue() fails
            // Avoid test pollution by putting the db back into a default state that other tests assume
            flyway.clean();
            flyway.migrate();
            TestUtils.cleanAndSeedDb(jdbcTemplate);
        }
    }

    protected String getDatabaseCatalog() {
        return MigrationTest.getDatabaseCatalog(jdbcTemplate);
    }
}
