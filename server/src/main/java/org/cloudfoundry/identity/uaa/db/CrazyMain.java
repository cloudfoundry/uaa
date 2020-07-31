package org.cloudfoundry.identity.uaa.db;


import org.springframework.context.support.ClassPathXmlApplicationContext;

public class CrazyMain {

  public static void main(String[] args) {
    System.out.println("humpty dumpty sat on a wall");
    new ClassPathXmlApplicationContext(
        "spring/env.xml",
        "spring/data-source.xml",
        "spring/jdbc-test-base-add-flyway.xml");
  }
}
