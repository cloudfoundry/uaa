package org.cloudfoundry.identity.uaa.db.beans;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.db.FixFailedBackportMigrations_4_0_4;
import org.flywaydb.core.Flyway;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

@Configuration
@Slf4j
public class FlywayConfiguration {

    /**
     * In Flyway 5, the default version table name changed to flyway_schema_history
     * https://flywaydb.org/documentation/releaseNotes#5.0.0
     * https://github.com/flyway/flyway/issues/1848
     * <p>
     * We need to maintain backwards compatibility due to {@link FixFailedBackportMigrations_4_0_4}
     */
    static final String VERSION_TABLE = "schema_version";
    static final String FLYWAY_CLEAN_DISABLED = "spring.flyway.clean-disabled";

    @Bean
    public Flyway baseFlyway(ApplicationContext context, DataSource dataSource, DatabaseProperties databaseProperties) {
        boolean cleanDisabled = context.getEnvironment().getProperty(FLYWAY_CLEAN_DISABLED, "true").equalsIgnoreCase("true");

        return Flyway.configure()
                .baselineOnMigrate(true)
                .dataSource(dataSource)
                .locations("classpath:org/cloudfoundry/identity/uaa/db/" + databaseProperties.getDatabasePlatform().type + "/")
                .baselineVersion("1.5.2")
                .validateOnMigrate(false)
                .table(VERSION_TABLE)
                .cleanDisabled(cleanDisabled)
                .load();
    }

    private static final String MIGRATIONS_ENABLED = "uaa.migrationsEnabled";

    @Configuration
    @Conditional(FlywayConfigurationWithMigration.ConfiguredWithMigrations.class)
    public static class FlywayConfigurationWithMigration {
        static class ConfiguredWithMigrations implements Condition {

            @Override
            public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
                var migrationsEnabled = context.getEnvironment().getProperty(MIGRATIONS_ENABLED, "true");
                return !"false".equals(migrationsEnabled);
            }
        }

        @Bean
        public Flyway flyway(Flyway baseFlyway) {
            org.apache.tomcat.jdbc.pool.DataSource ds =
                    (org.apache.tomcat.jdbc.pool.DataSource) baseFlyway.getConfiguration().getDataSource();
            updateSpringJdbcMigrationTypes(ds);
            baseFlyway.repair();
            baseFlyway.migrate();
            ds.purge();
            return baseFlyway;
        }

        /**
         * Normalizes legacy Flyway schema history rows by rewriting the migration {@code type}
         * from {@code SPRING_JDBC} to {@code JDBC}. This avoids the startup failure
         * "Unknown migration type 'SPRING_JDBC' found in schema history" before {@code repair()}/{@code migrate()}.
         * <p>
         * The update is only executed when the version table already exists; on a fresh install
         * there is nothing to normalize. Failures are logged but otherwise intentionally ignored.
         */
        static void updateSpringJdbcMigrationTypes(DataSource ds) {
            try (Connection conn = ds.getConnection()) {
                if (!versionTableExists(conn)) {
                    return;
                }
                try (Statement stmt = conn.createStatement()) {
                    stmt.executeUpdate("UPDATE %s SET type = 'JDBC' WHERE type = 'SPRING_JDBC'".formatted(VERSION_TABLE));
                    if (!conn.getAutoCommit()) {
                        conn.commit();
                    }
                }
            } catch (SQLException e) {
                log.warn("Failed to normalize SPRING_JDBC migration types in {}: {}", VERSION_TABLE, e.getMessage());
            }
        }

        private static boolean versionTableExists(Connection conn) throws SQLException {
            DatabaseMetaData metaData = conn.getMetaData();
            for (String tableName : new String[]{VERSION_TABLE, VERSION_TABLE.toUpperCase()}) {
                try (ResultSet tables = metaData.getTables(conn.getCatalog(), null, tableName, new String[]{"TABLE"})) {
                    if (tables.next()) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    @Configuration
    @Conditional(FlywayConfigurationWithoutMigrations.ConfiguredWithoutMigrations.class)
    static class FlywayConfigurationWithoutMigrations {

        static class ConfiguredWithoutMigrations implements Condition {

            @Override
            public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
                var migrationsEnabled = context.getEnvironment().getProperty(MIGRATIONS_ENABLED, "true");
                return "false".equals(migrationsEnabled);
            }
        }

        @Bean
        public Flyway flyway(Flyway baseFlyway) {
            return baseFlyway;
        }
    }
}

