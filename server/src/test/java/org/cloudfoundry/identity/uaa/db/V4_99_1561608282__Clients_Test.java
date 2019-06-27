package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.flywaydb.core.api.callback.Callback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertTrue;

class V4_99_1561608282__Clients_Callback implements Callback {

    private final Runnable runWhenPassed;

    V4_99_1561608282__Clients_Callback(Runnable runWhenPassed) {
        this.runWhenPassed = runWhenPassed;
    }

    @Override
    public boolean supports(Event event, Context context) {
        switch (event.getId()) {
            case "beforeEachMigrate":
            case "afterEachMigrate":
                return V4_99_1561608282__Clients_Test.THIS_VERSION.equals(context.getMigrationInfo().getVersion());
            default:
                return false;
        }
    }

    @Override
    public boolean canHandleInTransaction(Event event, Context context) {
        return false;
    }

    @Override
    public void handle(Event event, Context context) {
        try (Statement statement = context.getConnection().createStatement()) {
            if ("beforeEachMigrate".equals(event.getId())) {
                beforeEachMigrate(statement);
            } else if ("afterEachMigrate".equals(event.getId())) {
                afterEachMigrate(statement);
                runWhenPassed.run();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private void beforeEachMigrate(Statement statement) throws SQLException {
        statement.executeUpdate("INSERT INTO oauth_client_details (client_id, client_secret) VALUES ('client_id_with_bcrypt', '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG')");
        statement.executeUpdate("INSERT INTO oauth_client_details (client_id, client_secret) VALUES ('client_id_with_password', 'password')");
        statement.executeUpdate("INSERT INTO oauth_client_details (client_id, client_secret) VALUES ('client_id_with_null_password', NULL)");
    }

    private void afterEachMigrate(Statement statement) throws SQLException {
        ResultSet resultSet = statement.executeQuery("select client_id, client_secret from oauth_client_details");
        int found = 0;
        while (resultSet.next()) {
            String client_id = resultSet.getString("client_id");
            String client_secret = resultSet.getString("client_secret");

            if ("client_id_with_bcrypt".equals(client_id)) {
                found++;
                if (!"{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG".equals(client_secret)) {
                    throw new Error("migration did not work for client_id=" + client_id);
                }
            }

            if ("client_id_with_password".equals(client_id)) {
                found++;
                if (!"{bcrypt}password".equals(client_secret)) {
                    throw new Error("migration did not work for client_id=" + client_id);
                }
            }

            if ("client_id_with_null_password".equals(client_id)) {
                found++;
                if (null != client_secret) {
                    throw new Error("migration did not work for client_id=" + client_id);
                }
            }
        }
        if (found != 3) {
            throw new Error("migration did not work - not all clients found");
        }
    }
}

@Nested
@WithDatabaseContext
class V4_99_1561608282__Clients_Test {

    static final MigrationVersion THIS_VERSION = MigrationVersion.fromVersion("4.99.1561608282");

    private boolean migrationPassed = false;

    @BeforeEach
    void setUp(@Autowired Flyway flyway) {
        flyway.clean();
        Flyway.configure()
                .configuration(flyway.getConfiguration())
                .callbacks(new V4_99_1561608282__Clients_Callback(() -> migrationPassed = true))
                .load()
                .migrate();
    }

    @Test
    void clientsMigration() {
        assertTrue(migrationPassed);
    }
}
