package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.output.InfoOutput;
import org.junit.Assert;

import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class MigrationTestRunner {
    private Flyway flyway;

    public MigrationTestRunner(Flyway flyway) {
        this.flyway = flyway;
    }

    public void run(MigrationTest... tests) {
        final int[] assertionsRan = {0};
        flyway.migrate();
        List<InfoOutput> migrationList = flyway.info().getInfoResult().migrations;
        List<InfoOutput> failedMigrations = migrationList.stream().filter(e -> !"success".equalsIgnoreCase((e.state))).collect(Collectors.toList());
        if (failedMigrations != null && !failedMigrations.isEmpty()) {
            Assert.fail(failedMigrations.size() + " of " + migrationList.size() + " migrations failed.");
        }
        for (MigrationTest test : tests) {
            if (migrationList.stream().anyMatch(e -> e.version.equalsIgnoreCase(test.getTargetMigration()))) {
                try {
                    test.runAssertions();
                } catch (Exception e) {
                    Assert.fail(e.getMessage());
                }
                assertionsRan[0]++;
            }

        }
        assertThat("Not every db migration ran", assertionsRan[0], is(tests.length));
    }
}
