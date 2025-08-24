package org.cloudfoundry.identity.uaa.impl.config;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.extensions.SpringProfileCleanupExtension;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.StandardServletEnvironment;

import jakarta.servlet.ServletContext;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Enumeration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer.YML_ENV_VAR_NAME;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.description;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(SpringProfileCleanupExtension.class)
@ExtendWith(LoggerContextCleanupExtension.class)
class YamlServletProfileInitializerTest {

    private YamlServletProfileInitializer initializer;
    private ConfigurableWebApplicationContext context;
    private StandardServletEnvironment environment;
    private ServletContext servletContext;

    private static final String NEW_LINE = System.lineSeparator();
    private Path tempDirectory;
    private AlphanumericRandomValueStringGenerator randomValueStringGenerator;

    @BeforeEach
    void setup() throws IOException {
        initializer = new YamlServletProfileInitializer();
        context = mock(ConfigurableWebApplicationContext.class);
        environment = new StandardServletEnvironment();
        servletContext = mock(ServletContext.class);

        when(servletContext.getInitParameterNames()).thenReturn(new EmptyEnumerationOfString());

        when(context.getServletContext()).thenReturn(servletContext);
        when(context.getEnvironment()).thenReturn(environment);
        Mockito.doAnswer((Answer<Void>) invocation -> {
            System.err.println(invocation.getArguments()[0]);
            return null;
        }).when(servletContext).log(anyString());
        when(servletContext.getContextPath()).thenReturn("/context");
        tempDirectory = Files.createTempDirectory("secrets-dir");
        tempDirectory.toFile().deleteOnExit();
        System.setProperty("SECRETS_DIR", tempDirectory.toString());
        randomValueStringGenerator = new AlphanumericRandomValueStringGenerator(10);
    }

    @AfterEach
    void cleanup() {
        System.clearProperty("CLOUDFOUNDRY_CONFIG_PATH");
        System.clearProperty("SECRETS_DIR");
    }

    @Test
    void loadDefaultResource() {
        when(context.getResource(contains("${CLOUDFOUNDRY_CONFIG_PATH}"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertThat(environment.getProperty("foo")).isEqualTo("bar");
        assertThat(environment.getProperty("spam.foo")).isEqualTo("baz");
    }

    @Test
    void activeProfiles() {
        System.setProperty("spring.profiles.active", "foo");

        when(context.getResource(anyString())).thenReturn(
                new ByteArrayResource("spring_profiles: bar".getBytes()));

        initializer.initialize(context);

        assertActiveProfilesAre(environment, "bar");
    }

    @Test
    void activeProfilesFromYaml() {
        when(context.getResource(anyString())).thenReturn(
                new ByteArrayResource("spring_profiles: bar".getBytes()));

        initializer.initialize(context);

        assertActiveProfilesAre(environment, "bar");
    }

    @Test
    void log4jConfigurationFromYaml() {
        when(context.getResource(anyString())).thenReturn(
                new ByteArrayResource("logging:\n  config: bar".getBytes()));
        initializer.initialize(context);
    }

    @Test
    void loadServletConfiguredFilename() {
        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "/config/path");
        when(context.getResource("file:/config/path/uaa.yml")).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertThat(environment.getProperty("foo")).isEqualTo("bar");
        assertThat(environment.getProperty("spam.foo")).isEqualTo("baz");
    }

    @Test
    void loadServletConfiguredResource() {
        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "anywhere");
        when(context.getResource("file:anywhere/uaa.yml")).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz-from-config".getBytes()));

        initializer.initialize(context);

        assertThat(environment.getProperty("foo")).isEqualTo("bar");
        assertThat(environment.getProperty("spam.foo")).isEqualTo("baz-from-config");
    }

    @Test
    void loadContextConfiguredResource() {
        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "foo/bar");
        when(context.getResource("file:foo/bar/uaa.yml")).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz-from-context".getBytes()));

        initializer.initialize(context);

        assertThat(environment.getProperty("foo")).isEqualTo("bar");
        assertThat(environment.getProperty("spam.foo")).isEqualTo("baz-from-context");
    }

    @Test
    void loadReplacedResource() {
        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "foo");

        when(context.getResource("file:foo/uaa.yml")).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertThat(environment.getProperty("foo")).isEqualTo("bar");
        assertThat(environment.getProperty("spam.foo")).isEqualTo("baz");
    }

    @Test
    void loadReplacedResourceFromFileLocation() {
        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "bar");

        when(context.getResource("file:bar/uaa.yml")).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertThat(environment.getProperty("foo")).isEqualTo("bar");
        assertThat(environment.getProperty("spam.foo")).isEqualTo("baz");
    }

    @Test
    void loggingConfigVariableWorks() {
        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "somewhere");
        when(context.getResource("file:somewhere/uaa.yml")).thenReturn(
                new ByteArrayResource("logging:\n  config: /some/path".getBytes()));
        initializer.initialize(context);
        assertThat(environment.getProperty("logging.config")).isEqualTo("/some/path");
        assertThat(environment.getProperty("smtp.host")).isNull();
        assertThat(environment.getProperty("smtp.port")).isNull();
    }

    @Test
    void loadsPropertiesFrom_CLOUDFOUNDRY_CONFIG_PATH() {
        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "somewhere");
        when(context.getResource("file:somewhere/uaa.yml")).thenReturn(
                new ByteArrayResource("smtp:\n  user: marissa\n  password: koala".getBytes()));
        initializer.initialize(context);
        assertThat(environment.getProperty("smtp.user")).isEqualTo("marissa");
        assertThat(environment.getProperty("smtp.password")).isEqualTo("koala");
    }

    @Test
    void filesListedLaterOverrideDuplicatedConfiguration() {
        System.setProperty("UAA_CONFIG_PATH", "somewhere");
        when(context.getResource("file:somewhere/uaa.yml")).thenReturn(
                new ByteArrayResource("smtp:\n  user: marissa\n  password: koala".getBytes()));

        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "elsewhere");
        when(context.getResource("file:elsewhere/uaa.yml")).thenReturn(
                new ByteArrayResource("smtp:\n  user: donkey\n  password: kong".getBytes()));
        initializer.initialize(context);

        assertThat(environment.getProperty("smtp.user")).isEqualTo("donkey");
        assertThat(environment.getProperty("smtp.password")).isEqualTo("kong");
    }

    @Test
    void filesDeepMergeYmlProperties() {
        System.setProperty("UAA_CONFIG_PATH", "somewhere");
        when(context.getResource("file:somewhere/uaa.yml")).thenReturn(
                new ByteArrayResource("smtp:\n  user: marissa\n  password: koala\n  host:\n    foo: bar".getBytes()));

        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "elsewhere");
        when(context.getResource("file:elsewhere/uaa.yml")).thenReturn(
                new ByteArrayResource("smtp:\n  host:\n    baz: foobar".getBytes()));
        initializer.initialize(context);

        assertThat(environment.getProperty("smtp.user")).isEqualTo("marissa");
        assertThat(environment.getProperty("smtp.password")).isEqualTo("koala");
        assertThat(environment.getProperty("smtp.host.foo")).isEqualTo("bar");
        assertThat(environment.getProperty("smtp.host.baz")).isEqualTo("foobar");
    }

    @Test
    void readingYamlFromEnvironment() {
        SystemEnvironmentAccessor env = new SystemEnvironmentAccessor() {
            @Override
            public String getEnvironmentVariable(String name) {
                return name.equals(YML_ENV_VAR_NAME) ?
                        """
                                uaa.url: http://uaa.test.url/
                                login.url: http://login.test.url/
                                smtp:
                                  host: mail.server.host
                                  port: 3535
                                """ :
                        null;
            }
        };
        initializer.setEnvironmentAccessor(env);
        initializer.initialize(context);
        assertThat(environment.getProperty("smtp.host")).isEqualTo("mail.server.host");
        assertThat(environment.getProperty("smtp.port")).isEqualTo("3535");
        assertThat(environment.getProperty("uaa.url")).isEqualTo("http://uaa.test.url/");
        assertThat(environment.getProperty("login.url")).isEqualTo("http://login.test.url/");
    }

    @Nested
    class WithFakeStdOut {

        private PrintStream originalOut;
        private PrintStream mockPrintStream;

        @BeforeEach
        void setUp() {
            originalOut = System.out;
            mockPrintStream = mock(PrintStream.class);
            System.setOut(mockPrintStream);
        }

        @AfterEach
        void tearDown() {
            System.setOut(originalOut);
        }

        @Test
        void ignoreDashDTomcatLoggingConfigVariable() {
            final String tomcatLogConfig = "-Djava.util.logging.config=/some/path/logging.properties";
            System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "foo");
            when(context.getResource("file:foo/uaa.yml"))
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
            initializer.initialize(context);
            assertThat(environment.getProperty("logging.config")).isEqualTo("-Djava.util.logging.config=/some/path/logging.properties");

            verify(mockPrintStream, description("Expected to find a log entry indicating that the LOGGING_CONFIG variable was found."))
                    .println("Ignoring Log Config Location: -Djava.util.logging.config=/some/path/logging.properties. Location is suspect to be a Tomcat startup script environment variable");
        }
    }

    private static class EmptyEnumerationOfString implements Enumeration<String> {
        @Override
        public boolean hasMoreElements() {
            return false;
        }

        @Override
        public String nextElement() {
            return null;
        }
    }

    @ExtendWith(PollutionPreventionExtension.class)
    @ExtendWith(SpringProfileCleanupExtension.class)
    @Nested
    class ApplySpringProfiles {

        private MockEnvironment environment;

        @BeforeEach
        void setup() {
            initializer = new YamlServletProfileInitializer();
            environment = new MockEnvironment();
        }

        @Test
        void tokenizeToStringArray_RemovesSpaces() {
            String profileString = "    database    ,  ldap ";
            String[] profiles = StringUtils.tokenizeToStringArray(profileString, ",", true, true);
            assertThat(profiles).hasSize(2);
            assertThat(profiles[0]).isEqualTo("database");
            assertThat(profiles[1]).isEqualTo("ldap");
            // And show what's wrong with commaDelimitedListToStringArray
            profiles = StringUtils.commaDelimitedListToStringArray(profileString);
            assertThat(profiles).hasSize(2);
            assertThat(profiles[0]).isEqualTo("    database    ");
            assertThat(profiles[1]).isEqualTo("  ldap ");
        }

        @Test
        void ifNoProfilesAreSetUseHsqldb() {
            System.clearProperty("spring.profiles.active");
            YamlServletProfileInitializer.applySpringProfiles(environment);
            assertActiveProfilesAre(environment, "hsqldb");
        }

        @Test
        void ifProfilesAreSetUseThem() {
            System.setProperty("spring.profiles.active", "hsqldb,ldap");
            YamlServletProfileInitializer.applySpringProfiles(environment);
            assertActiveProfilesAre(environment, "hsqldb", "ldap");
        }

        @Test
        void defaultProfileUnset() {
            System.setProperty("spring.profiles.active", "hsqldb");
            YamlServletProfileInitializer.applySpringProfiles(environment);
            assertActiveProfilesAre(environment, "hsqldb");
            assertThat(environment.getDefaultProfiles()).containsExactly(new String[0]);
        }

        @Test
        void yamlConfiguredProfilesAreUsed() {
            System.setProperty("spring.profiles.active", "hsqldb,ldap");
            environment.setProperty("spring_profiles", "mysql,ldap");
            YamlServletProfileInitializer.applySpringProfiles(environment);
            assertActiveProfilesAre(environment, "mysql", "ldap");
        }
    }

    @Test
    void appliesCustomClassPathLogProperties() throws Exception {
        File tempFile = Files.createTempFile("prefix", "suffix.properties").toFile();
        File validLog4j2PropertyFile = new ClassPathResource("log4j2-test.properties").getFile();

        FileUtils.copyFile(validLog4j2PropertyFile, tempFile);

        System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "anything");
        when(context.getResource("file:anything/uaa.yml"))
                .thenReturn(new ByteArrayResource(("logging:\n  config: " + tempFile.getAbsolutePath()).getBytes()));

        initializer.initialize(context);

        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);

        URI expectedUrl = ResourceUtils.toURI("file:" + tempFile.getAbsolutePath());

        assertThat(loggerContext.getConfigLocation()).isEqualTo(expectedUrl);

        tempFile.delete();
    }

    @ExtendWith(PollutionPreventionExtension.class)
    @ExtendWith(SpringProfileCleanupExtension.class)
    @Nested
    class WithArbitrarySecretYamlFiles {

        @Test
        void loadsConfigurationFromFilesInThe_SECRETS_DIR_Variable() {
            String fileName = createRandomSecretsFile();

            ByteArrayResource byteArrayResource = new ByteArrayResource(("hocus:" + NEW_LINE +
                    "  pocus: focus" + NEW_LINE +
                    "  foo: bar").getBytes());

            when(context.getResource("file:%s".formatted(fileName)))
                    .thenReturn(byteArrayResource);

            initializer.initialize(context);
            assertThat(environment.getProperty("hocus.pocus")).isEqualTo("focus");
            assertThat(environment.getProperty("hocus.foo")).isEqualTo("bar");
        }

        @Test
        void mergesAndOverridesUaaYml() {
            ByteArrayResource uaaYml = new ByteArrayResource(("database:" + NEW_LINE +
                    "  username: default-username" + NEW_LINE +
                    "  password: default-password" + NEW_LINE +
                    "  url: jdbc://hostname").getBytes());

            System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", "cloudfoundryconfigpath");
            when(context.getResource("file:cloudfoundryconfigpath/uaa.yml"))
                    .thenReturn(uaaYml);

            ByteArrayResource databaseCredentialsYml = new ByteArrayResource(("database:" + NEW_LINE +
                    "  username: donkey" + NEW_LINE +
                    "  password: kong").getBytes());

            String fileName = createSecretsFile("database_credentials.yml");

            when(context.getResource("file:%s".formatted(fileName)))
                    .thenReturn(databaseCredentialsYml);

            initializer.initialize(context);
            assertThat(environment.getProperty("database.username")).isEqualTo("donkey");
            assertThat(environment.getProperty("database.password")).isEqualTo("kong");
            assertThat(environment.getProperty("database.url")).isEqualTo("jdbc://hostname");
        }

        @Test
        void requiresYmlExtension() {
            String validFileName = createRandomSecretsFile();
            String inValidFileName = createSecretsFile("doesNotEndInYml");

            when(context.getResource("file:" + validFileName)).thenReturn(new ByteArrayResource("isValid: true".getBytes()));
            when(context.getResource("file:" + inValidFileName)).thenReturn(new ByteArrayResource("isNotValid: true".getBytes()));

            initializer.initialize(context);
            assertThat(environment.getProperty("isValid")).isEqualTo("true");
            assertThat(environment.getProperty("isNotValid")).isNull();
        }
    }

    private String createRandomSecretsFile() {
        return createSecretsFile("fileName-" + randomValueStringGenerator.generate() + ".yml");
    }

    private String createSecretsFile(String fileName) {
        File newFile = new File(tempDirectory.toAbsolutePath().toString(), fileName);
        try {
            newFile.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        newFile.deleteOnExit();
        return newFile.getAbsolutePath();
    }

    private static void assertActiveProfilesAre(
            final AbstractEnvironment environment,
            final String... profiles
    ) {
        assertThat(Arrays.asList(environment.getActiveProfiles())).containsExactlyInAnyOrder(profiles);
    }

}
