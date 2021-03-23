package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static java.lang.System.getProperties;
import static org.junit.Assume.assumeTrue;

@RunWith(SpringJUnit4ClassRunner.class)
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
    private boolean dbNeedsResetting = false;

    protected abstract String onlyRunTestsForActiveSpringProfileName();

    @Before
    public void setup() {
        String active = getProperties().getProperty("spring.profiles.active");
        assumeTrue("Expected db profile to be enabled", active != null && active.contains(onlyRunTestsForActiveSpringProfileName()));

        dbNeedsResetting = true;
        flyway.clean();
        migrationTestRunner = new MigrationTestRunner(flyway);
    }

    @After
    public void cleanup() {
        if (dbNeedsResetting) { // cleanup() is always called, even when setup()'s assumeTrue() fails
            // Avoid test pollution by putting the db back into a default state that other tests assume
            flyway.clean();
            flyway.migrate();
            TestUtils.cleanAndSeedDb(jdbcTemplate);
        }
    }
}
