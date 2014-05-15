package org.cloudfoundry.identity.uaa.test;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;

@Configuration
@ImportResource({"file:./src/main/webapp/WEB-INF/spring-servlet.xml", "file:./src/test/resources/ldap-test-server.xml"})
public class LdapIntegrationTestConfig  {
}
