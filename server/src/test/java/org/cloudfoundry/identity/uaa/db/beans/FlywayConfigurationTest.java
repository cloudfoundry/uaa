package org.cloudfoundry.identity.uaa.db.beans;

import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration.FlywayConfigurationWithMigration.ConfiguredWithMigrations;
import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration.FlywayConfigurationWithoutMigrations.ConfiguredWithoutMigrations;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

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
        when(mockConditionContext.getEnvironment()).thenReturn(mockEnvironment);
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
}