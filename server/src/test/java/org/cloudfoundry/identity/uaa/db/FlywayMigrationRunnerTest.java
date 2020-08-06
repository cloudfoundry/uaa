package org.cloudfoundry.identity.uaa.db;



import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


import java.util.HashMap;
import java.util.Map;
import org.cloudfoundry.identity.uaa.db.migration.UaaFlywayMigrationConfigurationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;

class FlywayMigrationRunnerTest {
  private Map<String, String> fakeEnv;

  @BeforeEach
  void setUp() {
    fakeEnv = new HashMap<>();
    fakeEnv.put("DB_USERNAME", "username");
    fakeEnv.put("DB_PASSWORD", "password");
    fakeEnv.put("DB_URL", "url");
    fakeEnv.put("DB_SCHEME", "scheme");
  }

  @Test
  void getPropertiesFromEnv_extractsExpectedValuesFromEnv()
      throws UaaFlywayMigrationConfigurationException {

    assertThatCode(() -> FlywayMigrationRunner.getPropertiesFromEnv(fakeEnv))
        .doesNotThrowAnyException();

    MapPropertySource p = FlywayMigrationRunner.getPropertiesFromEnv(fakeEnv);
    assertThat(fakeEnv.get("DB_USERNAME")).isEqualTo(p.getProperty("database.username"));
    assertThat(fakeEnv.get("DB_PASSWORD")).isEqualTo(p.getProperty("database.password"));
    assertThat(fakeEnv.get("DB_URL")).isEqualTo(p.getProperty("database.url"));
    assertThat(fakeEnv.get("DB_SCHEME")).isEqualTo(p.getProperty("spring.profiles.active"));
  }

  @Test
  void getPropertiesFromEnv_ThrowsAnException_WhenMissingDatabaseUsername() {
    assertThatExceptionIsThrownWhenEnvVarIsAbsent("DB_USERNAME");
  }

  @Test
  void getPropertiesFromEnv_ThrowsAnException_WhenMissingDatabasePassword() {
    assertThatExceptionIsThrownWhenEnvVarIsAbsent("DB_PASSWORD");
  }

  @Test
  void getPropertiesFromEnv_ThrowsAnException_WhenMissingDatabaseUrl() {
    assertThatExceptionIsThrownWhenEnvVarIsAbsent("DB_URL");
  }

  @Test
  void getPropertiesFromEnv_ThrowsAnException_WhenMissingDatabaseScheme() {
    assertThatExceptionIsThrownWhenEnvVarIsAbsent("DB_SCHEME");
  }

  private void assertThatExceptionIsThrownWhenEnvVarIsAbsent(String envVarName) {
    fakeEnv.remove(envVarName);

    assertThatThrownBy(() -> FlywayMigrationRunner.getPropertiesFromEnv(fakeEnv))
        .isInstanceOf(UaaFlywayMigrationConfigurationException.class)
        .hasMessage("Expected to find non-blank value for " + envVarName);
  }
}