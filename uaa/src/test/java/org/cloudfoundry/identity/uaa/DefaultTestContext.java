package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.db.beans.JdbcUrlCustomizer;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.ldap.LdapAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.session.SessionAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = {
        SpringServletTestConfig.class,
        TestClientAndMockMvcTestConfig.class,
        DatabasePropertiesOverrideConfiguration.class,
})
@EnableAutoConfiguration(exclude = {
        // Conflicts with UaaJdbcSessionConfig
        SessionAutoConfiguration.class,
        // Conflicts with LdapSearchAndCompareConfig/LdapSearchAndBindConfig/LdapSimpleBindConfig
        LdapAutoConfiguration.class,
        SecurityAutoConfiguration.class
})
public @interface DefaultTestContext {
}

@ImportResource(locations = {"file:./src/main/webapp/WEB-INF/spring-servlet.xml"})
@PropertySource(value = "classpath:integration_test_properties.yml", factory = NestedMapPropertySourceFactory.class)
class SpringServletTestConfig {

}

class TestClientAndMockMvcTestConfig {
    @Bean
    public MockMvc mockMvc(
            WebApplicationContext webApplicationContext,
            @Qualifier(UaaConfig.SPRING_SECURITY_FILTER_CHAIN_ID) FilterChainProxy securityFilterChain
    ) {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(securityFilterChain)
                .build();
    }

    @Bean
    public TestClient testClient(
            MockMvc mockMvc
    ) {
        return new TestClient(mockMvc);
    }

}

class DatabasePropertiesOverrideConfiguration {

    /**
     * Update the database name to have one DB per gradle process.
     * To learn more, read docs/testing.md.
     * <p>
     * This code was lifted from {@code TestDatabaseNameCustomizer}, since we do not produce
     * a shared test jar across projects.
     */
    @Bean
    public JdbcUrlCustomizer testJdbcUrlCustomizer() {
        return url -> {
            // If we are not running in gradle, do not customize.
            var gradleWorkerId = System.getProperty("org.gradle.test.worker");
            if (gradleWorkerId == null) {
                return url;
            }

            // If the URL has already been customized, do not update
            var testDatabaseName = "uaa_" + gradleWorkerId;
            if (url.contains(testDatabaseName)) {
                return url;
            }

            // Change the URL name to "uaa_ID"
            return url.replace("uaa", testDatabaseName);
        };
    }

}
