package org.cloudfoundry.identity.uaa.db.beans;

import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration.FlywayConfigurationWithMigration;
import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration.FlywayConfigurationWithMigration.ConfiguredWithMigrations;
import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration.FlywayConfigurationWithoutMigrations.ConfiguredWithoutMigrations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.env.MockEnvironment;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class FlywayConfigurationTest {

    @Mock
    private ConditionContext mockConditionContext;

    private MockEnvironment mockEnvironment;

    private ConfiguredWithMigrations configuredWithMigrations;

    private ConfiguredWithoutMigrations configuredWithoutMigrations;

    @BeforeEach
    void setUp() {
        mockEnvironment = new MockEnvironment();
        lenient().when(mockConditionContext.getEnvironment()).thenReturn(mockEnvironment);
        configuredWithMigrations = new ConfiguredWithMigrations();
        configuredWithoutMigrations = new ConfiguredWithoutMigrations();
    }

    @Test
    void flywayConfiguration_RunsMigrations_WhenTheConfigurationIsNotSet() {
        assertThat(configuredWithMigrations.matches(mockConditionContext, null)).isTrue();
        assertThat(configuredWithoutMigrations.matches(mockConditionContext, null)).isFalse();
    }

    @Test
    void flywayConfiguration_RunsMigrations_WhenTheyAreEnabled() {
        mockEnvironment.setProperty("uaa.migrationsEnabled", "true");

        assertThat(configuredWithMigrations.matches(mockConditionContext, null)).isTrue();
        assertThat(configuredWithoutMigrations.matches(mockConditionContext, null)).isFalse();
    }

    @Test
    void flywayConfiguration_RunsMigrations_WhenTheyAreDisabled() {
        mockEnvironment.setProperty("uaa.migrationsEnabled", "false");

        assertThat(configuredWithMigrations.matches(mockConditionContext, null)).isFalse();
        assertThat(configuredWithoutMigrations.matches(mockConditionContext, null)).isTrue();
    }

    @Test
    void flywayConfiguration_RunsMigration_WhenInvalidConfiguration() {
        mockEnvironment.setProperty("uaa.migrationsEnabled", "bogus");

        assertThat(configuredWithMigrations.matches(mockConditionContext, null)).isTrue();
        assertThat(configuredWithoutMigrations.matches(mockConditionContext, null)).isFalse();
    }

    private DataSource dataSource;

    @AfterEach
    void tearDown() throws SQLException {
        if (dataSource != null) {
            try (Connection conn = dataSource.getConnection();
                 Statement stmt = conn.createStatement()) {
                stmt.execute("SHUTDOWN");
            }
        }
    }

    private DataSource inMemoryDataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.hsqldb.jdbc.JDBCDriver");
        ds.setUrl("jdbc:hsqldb:mem:" + UUID.randomUUID());
        ds.setUsername("sa");
        ds.setPassword("");
        return ds;
    }

    private void createSchemaVersionTable(DataSource ds) throws SQLException {
        try (Connection conn = ds.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE %s (installed_rank INT, type VARCHAR(20))".formatted(FlywayConfiguration.VERSION_TABLE));
        }
    }

    private String typeForRank(DataSource ds, int rank) throws SQLException {
        try (Connection conn = ds.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT type FROM %s WHERE installed_rank = %d".formatted(FlywayConfiguration.VERSION_TABLE, rank))) {
            return rs.next() ? rs.getString("type") : null;
        }
    }

    @Test
    void updateSpringJdbcMigrationTypes_RewritesSpringJdbcToJdbc() throws SQLException {
        dataSource = inMemoryDataSource();
        createSchemaVersionTable(dataSource);
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("INSERT INTO %s (installed_rank, type) VALUES (1, 'SPRING_JDBC')".formatted(FlywayConfiguration.VERSION_TABLE));
            stmt.execute("INSERT INTO %s (installed_rank, type) VALUES (2, 'SQL')".formatted(FlywayConfiguration.VERSION_TABLE));
        }

        FlywayConfigurationWithMigration.updateSpringJdbcMigrationTypes(dataSource);

        assertThat(typeForRank(dataSource, 1)).isEqualTo("JDBC");
        assertThat(typeForRank(dataSource, 2)).isEqualTo("SQL");
    }

    @Test
    void updateSpringJdbcMigrationTypes_DoesNotThrow_WhenVersionTableMissing() {
        dataSource = inMemoryDataSource();

        FlywayConfigurationWithMigration.updateSpringJdbcMigrationTypes(dataSource);
        assertThat(dataSource).isNotNull();
    }
}