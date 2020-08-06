package org.cloudfoundry.identity.uaa.db;

import org.springframework.context.support.ClassPathXmlApplicationContext;

public class FlywayMigrationRunner {

  public static void main(String[] args) {
    // TODO ensure that we do this safely and fail with a reasonable error
    System.setProperty("database.username", System.getenv("DB_USERNAME"));
    System.setProperty("database.password", System.getenv("DB_PASSWORD"));
    System.setProperty("database.url", System.getenv("DB_URL"));
    System.setProperty("spring.profiles.active", System.getenv("DB_SCHEME"));
    new ClassPathXmlApplicationContext(
        "spring/env.xml",
        "spring/data-source.xml",
        "spring/jdbc-include-flyway.xml");
  }
}
