package org.cloudfoundry.identity.uaa.db;

import com.google.common.collect.Maps;
import java.util.Map;
import org.cloudfoundry.identity.uaa.db.migration.UaaFlywayMigrationConfigurationException;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.env.MapPropertySource;

public class FlywayMigrationRunner {

  public static void main(String[] args) throws UaaFlywayMigrationConfigurationException {
    ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext();

    context.getEnvironment().getPropertySources().addLast(getPropertiesFromEnv(System.getenv()));

    context.setConfigLocations(
        "spring/env.xml",
        "spring/data-source.xml",
        "spring/jdbc-include-flyway.xml"
    );

    context.refresh();
  }

  public static MapPropertySource getPropertiesFromEnv(Map<String, String> envMap)
      throws UaaFlywayMigrationConfigurationException {
    Map<String, Object> properties = Maps.newHashMap();
    properties.put("database.username", getValueFromEnv(envMap, "DB_USERNAME"));
    properties.put("database.password", getValueFromEnv(envMap, "DB_PASSWORD"));
    properties.put("database.url", getValueFromEnv(envMap, "DB_URL"));
    properties.put("spring.profiles.active", getValueFromEnv(envMap, "DB_SCHEME"));

    return new MapPropertySource("properties", properties);
  }

  private static String getValueFromEnv(Map<String, String> envMap, String envVarName)
      throws UaaFlywayMigrationConfigurationException {
    String envValue = envMap.get(envVarName);
    if (envValue == null || envValue.isBlank()) {
      throw new UaaFlywayMigrationConfigurationException(
          String.format("Expected to find non-blank value for %s", envVarName)
      );
    }
    return envValue;
  }
}
