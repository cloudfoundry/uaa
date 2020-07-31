package org.cloudfoundry.identity.uaa.db.beans;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import javax.sql.DataSource;
import org.cloudfoundry.identity.uaa.db.DataSourceAccessor;
import org.cloudfoundry.identity.uaa.db.FixFailedBackportMigrations_4_0_4;
import org.cloudfoundry.identity.uaa.db.postgresql.V1_5_3__InitialDBScript;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.type.AnnotatedTypeMetadata;

@Configuration
public class FlywayConfiguration {

  /**
   * In Flyway 5, the default version table name changed to flyway_schema_history
   * https://flywaydb.org/documentation/releaseNotes#5.0.0
   * https://github.com/flyway/flyway/issues/1848
   * <p>
   * We need to maintain backwards compatibility due to {@link FixFailedBackportMigrations_4_0_4}
   */
  static final String VERSION_TABLE = "schema_version";

  /**
   * @param dataSourceAccessor This bean does NOT need need an instance of {@link DataSourceAccessor}.
   *                           However, other Flyway objects (example {@link V1_5_3__InitialDBScript}
   *                           DO make use of {@link DataSourceAccessor}
   */
  @Bean
  public Flyway baseFlyway(
      DataSource dataSource,
      DataSourceAccessor dataSourceAccessor,
      @Qualifier("platform") String platform) {

    Flyway flyway = Flyway.configure()
        .baselineOnMigrate(true)
        .dataSource(dataSource)
        .locations("classpath:org/cloudfoundry/identity/uaa/db/" + platform + "/")
        .baselineVersion("1.5.2")
        .validateOnMigrate(false)
        .table(VERSION_TABLE)
        .load();
    System.out.println(Arrays.toString(flyway.getConfiguration().getLocations()));
    try {
      Files.list(
          Paths.get("classpath:org/cloudfoundry/identity/uaa/db/" + platform + "/"))
          .forEach(x -> System.out.println(x.toString()));
    } catch(Exception e) {
      System.out.println(e.toString());
    }
    return flyway;
  }

  private static final String MIGRATIONS_ENABLED = "uaa.migrationsEnabled";

  @Configuration
  @Conditional(FlywayConfigurationWithMigration.ConfiguredWithMigrations.class)
  public static class FlywayConfigurationWithMigration {
    static class ConfiguredWithMigrations implements Condition {

      @Override
      public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        var migrationsEnabled = context.getEnvironment().getProperty(MIGRATIONS_ENABLED, "true");
        return !migrationsEnabled.equals("false");
      }
    }

    @Bean
    public Flyway flyway(Flyway baseFlyway) {
      System.out.println(Arrays.toString(baseFlyway.getConfiguration().getLocations()));
      try {
        Files.list(
            Paths.get("classpath:org/cloudfoundry/identity/uaa/db/" + "mysql" + "/"))
            .forEach(x -> System.out.println(x.toString()));
      } catch(Exception e) {
        System.out.println(e.toString());
      }
      System.out.println("Migrations will be fun!");
      baseFlyway.repair();
      baseFlyway.migrate();
      System.out.println("Migrations have been fun!");
      return baseFlyway;
    }
  }

  @Configuration
  @Conditional(FlywayConfigurationWithoutMigrations.ConfiguredWithoutMigrations.class)
  static class FlywayConfigurationWithoutMigrations {

    static class ConfiguredWithoutMigrations implements Condition {

      @Override
      public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        var migrationsEnabled = context.getEnvironment().getProperty(MIGRATIONS_ENABLED, "true");
        return migrationsEnabled.equals("false");
      }
    }

    @Bean
    public Flyway flyway(Flyway baseFlyway) {
      return baseFlyway;
    }
  }
}

