package org.cloudfoundry.identity.uaa.db;

import org.springframework.context.support.ClassPathXmlApplicationContext;

public class FlywayMigrationRunner {

  public static void main(String[] args) {
    new ClassPathXmlApplicationContext(
        "spring/env.xml",
        "spring/data-source.xml",
        "spring/jdbc-include-flyway.xml");
  }
}
