package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.callback.BaseFlywayCallback;
import org.junit.Assert;

import java.sql.Connection;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class MigrationTestRunner {
    private Flyway flyway;

    public MigrationTestRunner(Flyway flyway) {
        this.flyway = flyway;
    }

    public void run(MigrationTest... tests) {
        final int[] assertionsRan = {0};
        flyway.setCallbacks(new BaseFlywayCallback() {
            @Override
            public void afterEachMigrate(Connection connection, MigrationInfo info) {
                super.afterEachMigrate(connection, info);
                for (MigrationTest test : tests) {
                    if (test.getTargetMigration().equals(info.getVersion().getVersion())) {
                        try {
                            test.runAssertions();
                        } catch (Exception e) {
                            Assert.fail(e.getMessage());
                        }
                        assertionsRan[0]++;
                    }
                }
            }
        });
        flyway.migrate();

        assertThat(assertionsRan[0], is(tests.length));
    }
}
