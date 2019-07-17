package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.flywaydb.core.api.callback.Callback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertTrue;

class V4_99_1561608282__Users_Callback implements Callback {

    private final Runnable runWhenPassed;

    V4_99_1561608282__Users_Callback(Runnable runWhenPassed) {
        this.runWhenPassed = runWhenPassed;
    }

    @Override
    public boolean supports(Event event, Context context) {
        switch (event.getId()) {
            case "beforeEachMigrate":
            case "afterEachMigrate":
                return V4_99_1561658666__Users_Test.THIS_VERSION.equals(context.getMigrationInfo().getVersion());
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
        statement.executeUpdate("INSERT INTO users (id, username, email, password) VALUES ('user_id_with_bcryptXXXXXXXXXXXXXXXXX', 'username1', 'email1', '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG')");
        statement.executeUpdate("INSERT INTO users (id, username, email, password) VALUES ('user_id_with_passwordXXXXXXXXXXXXXXX', 'username2', 'email2', 'password')");
        statement.executeUpdate("INSERT INTO users (id, username, email, password) VALUES ('user_id_with_empty_passwordXXXXXXXXX', 'username3', 'email3', '')");
    }

    private void afterEachMigrate(Statement statement) throws SQLException {
        ResultSet resultSet = statement.executeQuery("select id, password from users");
        int found = 0;
        while (resultSet.next()) {
            String user_id = resultSet.getString("id");
            String user_password = resultSet.getString("password");

            if ("user_id_with_bcryptXXXXXXXXXXXXXXXXX".equals(user_id)) {
                found++;
                if (!"{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG".equals(user_password)) {
                    throw new Error("migration did not work for user_id=" + user_id);
                }
            }

            if ("user_id_with_passwordXXXXXXXXXXXXXXX".equals(user_id)) {
                found++;
                if (!"{bcrypt}password".equals(user_password)) {
                    throw new Error("migration did not work for user_id=" + user_id);
                }
            }

            if ("user_id_with_empty_passwordXXXXXXXXX".equals(user_id)) {
                found++;
                if (!"{bcrypt}".equals(user_password)) {
                    throw new Error("migration did not work for user_id=" + user_id);
                }
            }
        }
        if (found != 3) {
            throw new Error("migration did not work - could not find users");
        }
    }
}

@WithDatabaseContext
class V4_99_1561658666__Users_Test {

    static final MigrationVersion THIS_VERSION = MigrationVersion.fromVersion("4.99.1561658666");
    private boolean migrationPassed = false;

    @BeforeEach
    void setUp(@Autowired Flyway flyway) {
        flyway.clean();
        Flyway.configure()
                .configuration(flyway.getConfiguration())
                .callbacks(new V4_99_1561608282__Users_Callback(() -> migrationPassed = true))
                .load()
                .migrate();
    }

    @Test
    @Disabled
    void usersMigration() {
        assertTrue(migrationPassed);
    }
}
