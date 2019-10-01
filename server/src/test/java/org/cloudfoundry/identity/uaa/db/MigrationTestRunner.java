package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.callback.BaseCallback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.flywaydb.core.api.configuration.Configuration;
import org.junit.Assert;

import java.sql.SQLException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class MigrationTestRunner {
    private Flyway flyway;

    public MigrationTestRunner(Flyway flyway) {
        this.flyway = flyway;
    }

    public void run(MigrationTest... tests) {
        final int[] assertionsRan = {0};
        BaseCallback callback = new BaseCallback() {
            @Override
            public boolean supports(Event event, Context context) {
                return event == Event.AFTER_EACH_MIGRATE;
            }

            @Override
            public boolean canHandleInTransaction(Event event, Context context) {
                return true;
            }

            @Override
            public void handle(Event event, Context context) {
                try {
                    context.getConnection().commit();
                } catch (SQLException e) {
                    Assert.fail(e.getMessage());
                }

                for (MigrationTest test : tests) {
                    if (test.getTargetMigration().equals(context.getMigrationInfo().getVersion().getVersion())) {
                        try {
                            test.runAssertions();
                        } catch (Exception e) {
                            Assert.fail(e.getMessage());
                        }
                        assertionsRan[0]++;
                    }
                }
            }
        };

        Configuration configuration = flyway.getConfiguration();
        Flyway migrationFlyway = Flyway.configure()
                .baselineOnMigrate(true)
                .dataSource(configuration.getDataSource())
                .locations(configuration.getLocations())
                .baselineVersion(configuration.getBaselineVersion())
                .validateOnMigrate(false)
                .table(configuration.getTable())
                .callbacks(callback)
                .load();

        migrationFlyway.migrate();

        assertThat("Not every db migration ran", assertionsRan[0], is(tests.length));
    }
}
