package org.cloudfoundry.identity.uaa.impl.config;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.extensions.SpringProfileCleanupExtension;
import org.cloudfoundry.identity.uaa.extensions.SystemPropertiesCleanupExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.StandardServletEnvironment;

import javax.servlet.ServletConfig;
import java.io.File;
import java.net.URI;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(SpringProfileCleanupExtension.class)
@ExtendWith(LoggerContextCleanupExtension.class)
@ExtendWith(MockitoExtension.class)
class YamlServletProfileInitializerTest {

    private YamlServletProfileInitializer initializer;
    private ConfigurableEnvironment environment;
    @Mock
    private ConfigurableWebApplicationContext mockConfigurableWebApplicationContext;
    @Mock
    private ServletConfig mockServletConfig;

    @RegisterExtension
    @SuppressWarnings("unused")
    static final SystemPropertiesCleanupExtension systemPropertiesCleanupExtension = new SystemPropertiesCleanupExtension(
            "APPLICATION_CONFIG_FILE",
            "APPLICATION_CONFIG_URL",
            "spring.profiles.active");

    @BeforeEach
    void setup() {
        initializer = new YamlServletProfileInitializer();
        environment = new StandardServletEnvironment();

        when(mockConfigurableWebApplicationContext.getServletConfig()).thenReturn(mockServletConfig);
        when(mockConfigurableWebApplicationContext.getEnvironment()).thenReturn(environment);
        when(mockConfigurableWebApplicationContext.getResource(anyString())).thenReturn(null);
    }

    @Test
    void loadDefaultResource() {
        when(mockConfigurableWebApplicationContext.getResource("${APPLICATION_CONFIG_URL}")).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    void activeProfiles() {
        System.setProperty("spring.profiles.active", "foo");

        when(mockConfigurableWebApplicationContext.getResource(anyString())).thenReturn(
                new ByteArrayResource("spring_profiles: bar".getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        assertEquals("bar", environment.getActiveProfiles()[0]);
    }

    @Test
    void activeProfilesFromYaml() {
        when(mockConfigurableWebApplicationContext.getResource("${APPLICATION_CONFIG_URL}")).thenReturn(
                new ByteArrayResource("spring_profiles: bar".getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        assertEquals("bar", environment.getActiveProfiles()[0]);
    }

    @Test
    void log4jConfigurationFromYaml() {
        when(mockConfigurableWebApplicationContext.getResource("${APPLICATION_CONFIG_URL}")).thenReturn(
                new ByteArrayResource("logging:\n  config: bar".getBytes()));
        initializer.initialize(mockConfigurableWebApplicationContext);
    }

    @Test
    void loadServletConfiguredFilename() {
        System.setProperty("APPLICATION_CONFIG_FILE", "/config/path/uaa.yml");
        when(mockConfigurableWebApplicationContext.getResource(ArgumentMatchers.eq("file:/config/path/uaa.yml"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    void loadServletConfiguredResource() {
        when(mockConfigurableWebApplicationContext.getResource("${APPLICATION_CONFIG_URL}")).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz-from-config".getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz-from-config", environment.getProperty("spam.foo"));
    }

    @Test
    void loadContextConfiguredResource() {
        when(mockConfigurableWebApplicationContext.getResource("${APPLICATION_CONFIG_URL}")).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz-from-context".getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz-from-context", environment.getProperty("spam.foo"));
    }

    @Test
    void loadReplacedResource() {
        System.setProperty("APPLICATION_CONFIG_URL", "file:foo/uaa.yml");

        when(mockConfigurableWebApplicationContext.getResource(ArgumentMatchers.eq("file:foo/uaa.yml"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    void loadReplacedResourceFromFileLocation() {
        System.setProperty("APPLICATION_CONFIG_URL", "file:foo/uaa.yml");

        when(mockConfigurableWebApplicationContext.getResource(ArgumentMatchers.eq("file:foo/uaa.yml"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    void loggingConfigVariableWorks() {
        System.setProperty("APPLICATION_CONFIG_FILE", "foo/uaa.yml");
        when(mockConfigurableWebApplicationContext.getResource(ArgumentMatchers.eq("file:foo/uaa.yml"))).thenReturn(
                new ByteArrayResource("logging:\n  config: /some/path".getBytes()));
        initializer.initialize(mockConfigurableWebApplicationContext);
        assertEquals("/some/path", environment.getProperty("logging.config"));
        assertNull(environment.getProperty("smtp.host"));
        assertNull(environment.getProperty("smtp.port"));
    }

    @Test
    void readingYamlFromEnvironment() {
        SystemEnvironmentAccessor env = new SystemEnvironmentAccessor() {
            @Override
            public String getEnvironmentVariable(String name) {
                return "UAA_CONFIG_YAML".equals(name) ?
                        "uaa.url: http://uaa.test-from-env.url/\n" +
                                "login.url: http://login.test.url/\n" +
                                "smtp:\n" +
                                "  host: mail.server.host\n" +
                                "  port: 3535\n" :
                        null;
            }
        };
        initializer.setEnvironmentAccessor(env);
        initializer.initialize(mockConfigurableWebApplicationContext);
        assertEquals("mail.server.host", environment.getProperty("smtp.host"));
        assertEquals("3535", environment.getProperty("smtp.port"));
        assertEquals("http://uaa.test-from-env.url/", environment.getProperty("uaa.url"));
        assertEquals("http://login.test.url/", environment.getProperty("login.url"));
    }

    @Test
    void ignoreDashDTomcatLoggingConfigVariable() {
        final String tomcatLogConfig = "-Djava.util.logging.config=/some/path/logging.properties";
        System.setProperty("APPLICATION_CONFIG_FILE", "foo/uaa.yml");
        when(mockConfigurableWebApplicationContext.getResource(ArgumentMatchers.eq("file:foo/uaa.yml")))
                .thenReturn(new ByteArrayResource(("logging:\n  config: " + tomcatLogConfig).getBytes()));
        environment.getPropertySources().addFirst(new PropertySource<Object>(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME) {
            @Override
            public boolean containsProperty(String name) {
                if ("LOGGING_CONFIG".equals(name)) {
                    return true;
                } else {
                    return super.containsProperty(name);
                }
            }

            @Override
            public Object getProperty(String name) {
                if ("LOGGING_CONFIG".equals(name)) {
                    return tomcatLogConfig;
                } else {
                    return System.getenv(name);
                }

            }
        });
        initializer.initialize(mockConfigurableWebApplicationContext);
        assertEquals("-Djava.util.logging.config=/some/path/logging.properties", environment.getProperty("logging.config"));
    }

    @ExtendWith(PollutionPreventionExtension.class)
    @ExtendWith(SpringProfileCleanupExtension.class)
    @ExtendWith(LoggerContextCleanupExtension.class)
    @ExtendWith(MockitoExtension.class)
    @Nested
    class ApplySpringProfiles {

        @RegisterExtension
        @SuppressWarnings("unused")
        final SystemPropertiesCleanupExtension systemPropertiesCleanupExtension = new SystemPropertiesCleanupExtension(
                "APPLICATION_CONFIG_FILE",
                "APPLICATION_CONFIG_URL",
                "spring.profiles.active");

        private MockEnvironment environment;

        @BeforeEach
        void setup() {
            initializer = new YamlServletProfileInitializer();
            environment = new MockEnvironment();
            reset(mockConfigurableWebApplicationContext);
        }

        @Test
        void tokenizeToStringArray_RemovesSpaces() {
            String profileString = "    database    ,  ldap ";
            String[] profiles = StringUtils.tokenizeToStringArray(profileString, ",", true, true);
            assertThat(profiles.length, is(2));
            assertThat(profiles[0], is("database"));
            assertThat(profiles[1], is("ldap"));
            // And show what's wrong with commaDelimitedListToStringArray
            profiles = StringUtils.commaDelimitedListToStringArray(profileString);
            assertThat(profiles.length, is(2));
            assertThat(profiles[0], is("    database    "));
            assertThat(profiles[1], is("  ldap "));
        }

        @Test
        void ifNoProfilesAreSetUseHsqldb() {
            System.clearProperty("spring.profiles.active");
            initializer.applySpringProfiles(environment);
            assertArrayEquals(new String[]{"hsqldb"}, environment.getActiveProfiles());
        }

        @Test
        void ifProfilesAreSetUseThem() {
            System.setProperty("spring.profiles.active", "hsqldb,default");
            initializer.applySpringProfiles(environment);
            assertArrayEquals(new String[]{"hsqldb", "default"}, environment.getActiveProfiles());
        }

        @Test
        void defaultProfileUnset() {
            System.setProperty("spring.profiles.active", "hsqldb");
            initializer.applySpringProfiles(environment);
            assertArrayEquals(new String[]{"hsqldb"}, environment.getActiveProfiles());
            assertArrayEquals(new String[0], environment.getDefaultProfiles());
        }

        @Test
        void yamlConfiguredProfilesAreUsed() {
            System.setProperty("spring.profiles.active", "hsqldb,default");
            environment.setProperty("spring_profiles", "mysql,default");
            initializer.applySpringProfiles(environment);
            assertArrayEquals(new String[]{"mysql", "default"}, environment.getActiveProfiles());
        }
    }

    @Test
    void appliesDefaultClassPathLogProperties() throws Exception {
        initializer.initialize(mockConfigurableWebApplicationContext);

        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);

        URI expectedUrl = ResourceUtils.toURI(ResourceUtils.getURL("classpath:log4j2.properties"));

        assertThat(loggerContext.getConfigLocation(), is(expectedUrl));
    }

    @Test
    void appliesCustomClassPathLogProperties() throws Exception {
        File tempFile = File.createTempFile("prefix", "suffix.properties");
        File validLog4j2PropertyFile = new ClassPathResource("log4j2-test.properties").getFile();

        FileUtils.copyFile(validLog4j2PropertyFile, tempFile);

        System.setProperty("APPLICATION_CONFIG_FILE", "anything/uaa.yml");
        when(mockConfigurableWebApplicationContext.getResource("file:anything/uaa.yml"))
                .thenReturn(new ByteArrayResource(("logging:\n  config: " + tempFile.getAbsolutePath()).getBytes()));

        initializer.initialize(mockConfigurableWebApplicationContext);

        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);

        URI expectedUrl = ResourceUtils.toURI("file:" + tempFile.getAbsolutePath());

        assertThat(loggerContext.getConfigLocation(), is(expectedUrl));

        tempFile.delete();
    }
}
