package org.cloudfoundry.identity.uaa;

import jakarta.servlet.RequestDispatcher;
import org.cloudfoundry.experimental.boot.UaaBootConfiguration;
import org.cloudfoundry.identity.uaa.db.beans.JdbcUrlCustomizer;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.ldap.LdapAutoConfiguration;
import org.springframework.boot.autoconfigure.session.SessionAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.EventListener;

import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@EnableWebMvc
@SpringBootTest(
        properties = {
                "spring.main.allow-bean-definition-overriding=true",
                "spring.main.allow-circular-references=true",
                "logging.level.org.springframework.security=TRACE"
        },
        classes = {
                UaaBootConfiguration.class,
                UaaApplicationConfiguration.class,
                TestClientAndMockMvcTestConfig.class,
                DatabasePropertiesOverrideConfiguration.class
        },
        webEnvironment = SpringBootTest.WebEnvironment.MOCK
)
@SpringJUnitConfig(initializers = {TestPropertyInitializer.class, YamlServletProfileInitializer.class})
@EnableAutoConfiguration(exclude = {
        // Conflicts with UaaJdbcSessionConfig
        SessionAutoConfiguration.class,
        // Conflicts with LdapSearchAndCompareConfig/LdapSearchAndBindConfig/LdapSimpleBindConfig
        LdapAutoConfiguration.class
})
public @interface DefaultTestContext {
}

class TestPropertyInitializer implements ApplicationContextInitializer<ConfigurableWebApplicationContext> {

    @Override
    public void initialize(ConfigurableWebApplicationContext applicationContext) {
        System.setProperty("UAA_CONFIG_URL","classpath:integration_test_properties.yml");
    }
}

class TestClientAndMockMvcTestConfig {
    @Bean
    public MockMvc mockMvc(
            WebApplicationContext webApplicationContext,
            @Qualifier(SPRING_SECURITY_FILTER_CHAIN) FilterChainProxy securityFilterChain
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

    @Bean
    MockServletContext mockServletContext() {

        return new MockServletContext() {
            @Override
            @NonNull
            public RequestDispatcher getNamedDispatcher(@Nullable String path) {
                return new MockRequestDispatcher("/");
            }

            @Override
            @NonNull
            public String getVirtualServerName() {
                return "localhost";
            }

            @Override
            public <T extends EventListener> void addListener(@Nullable T t) {
                //no op
            }
        };
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


