package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.callback.BaseCallback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.flywaydb.core.api.configuration.ClassicConfiguration;
import org.junit.Assert;

import java.sql.SQLException;

import static org.flywaydb.core.api.callback.Event.AFTER_EACH_MIGRATE;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class MigrationTestRunner {
    private final Flyway flyway;

    public MigrationTestRunner(Flyway flyway) {
        this.flyway = flyway;
    }

    public void run(MigrationTest... tests) {
        final int[] assertionsRan = {0};

        ClassicConfiguration config = (ClassicConfiguration) flyway.getConfiguration();
        config.setCallbacks(new BaseCallback() {
            @Override
            public void handle(Event event, Context context) {
                if (AFTER_EACH_MIGRATE == event) {
                    try {
                        if (!context.getConnection().getAutoCommit()) {
                            context.getConnection().commit();
                        }
                    } catch (SQLException e) {
                        Assert.fail(e.getMessage());
                    }

                    for (MigrationTest test : tests) {
                        if (test.getTargetMigration().equals(
                                context.getMigrationInfo().getVersion().getVersion())) {
                            try {
                                test.runAssertions();
                            } catch (Exception e) {
                                Assert.fail(e.getMessage());
                            }
                            assertionsRan[0]++;
                        }
                    }
                }
            }
        });

        // Flyway 7+ does not support modifying an already initialized Flyway instance
        // So we need to initialize a new Flyway instance (that has identical configs as the runtime Flyway,
        // except with an additional callback) to use in tests
        Flyway afterEachMigrateCallbackFlyway = new Flyway(config);

        try {
            afterEachMigrateCallbackFlyway.migrate();
            assertThat("Not every db migration ran", assertionsRan[0], is(tests.length));
        }
        finally {
            afterEachMigrateCallbackFlyway.clean();
            afterEachMigrateCallbackFlyway.migrate();
        }
    }
}
