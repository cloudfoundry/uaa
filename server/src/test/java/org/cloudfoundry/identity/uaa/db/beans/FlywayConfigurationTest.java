package org.cloudfoundry.identity.uaa.db.beans;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;


import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration.FlywayConfigurationWithMigration.ConfiguredWithMigrations;
import org.cloudfoundry.identity.uaa.db.beans.FlywayConfiguration.FlywayConfigurationWithoutMigrations.ConfiguredWithoutMigrations;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.mock.env.MockEnvironment;

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
    assertTrue(configuredWithMigrations.matches(mockConditionContext, null));
    assertFalse(configuredWithoutMigrations.matches(mockConditionContext, null));
  }

  @Test
  void flywayConfiguration_RunsMigrations_WhenTheyAreEnabled() {
    mockEnvironment.setProperty("uaa.migrationsEnabled", "true");

    assertTrue(configuredWithMigrations.matches(mockConditionContext, null));
    assertFalse(configuredWithoutMigrations.matches(mockConditionContext, null));
  }

  @Test
  void flywayConfiguration_RunsMigrations_WhenTheyAreDisabled() {
    mockEnvironment.setProperty("uaa.migrationsEnabled", "false");

    assertFalse(configuredWithMigrations.matches(mockConditionContext, null));
    assertTrue(configuredWithoutMigrations.matches(mockConditionContext, null));
  }

  @Test
  void flywayConfiguration_RunsMigration_WhenInvalidConfiguration() {
    mockEnvironment.setProperty("uaa.migrationsEnabled", "bogus");

    assertTrue(configuredWithMigrations.matches(mockConditionContext, null));
    assertFalse(configuredWithoutMigrations.matches(mockConditionContext, null));
  }
}