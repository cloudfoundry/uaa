package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.*;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.util.Log4jConfigurer;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.StandardServletEnvironment;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import java.util.Enumeration;

import static org.junit.Assert.*;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.util.StringUtils.hasText;

public class YamlServletProfileInitializerTests {

    private YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();

    private ConfigurableWebApplicationContext context = Mockito.mock(ConfigurableWebApplicationContext.class);

    private StandardServletEnvironment environment = new StandardServletEnvironment();

    private ServletConfig servletConfig = Mockito.mock(ServletConfig.class);

    private ServletContext servletContext = Mockito.mock(ServletContext.class);

    private static String activeProfiles;

    @BeforeClass
    public static void saveProfiles() {
        activeProfiles = System.getProperty("spring.profiles.active");
    }

    @AfterClass
    public static void restoreProfiles() {
        if (activeProfiles != null) {
            System.setProperty("spring.profiles.active", activeProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

    @Before
    public void setup() {
        Mockito.when(servletConfig.getInitParameterNames()).thenReturn(new EmptyEnumerationOfString());
        Mockito.when(servletContext.getInitParameterNames()).thenReturn(new EmptyEnumerationOfString());

        Mockito.when(context.getServletConfig()).thenReturn(servletConfig);
        Mockito.when(context.getServletContext()).thenReturn(servletContext);
        Mockito.when(context.getEnvironment()).thenReturn(environment);
        Mockito.doAnswer((Answer<Void>) invocation -> {
            System.err.println(invocation.getArguments()[0]);
            return null;
        }).when(servletContext).log(ArgumentMatchers.anyString());
        Mockito.when(servletContext.getContextPath()).thenReturn("/context");
    }

    @After
    public void cleanup() throws Exception {
        System.clearProperty("APPLICATION_CONFIG_URL");
        System.clearProperty("LOG_FILE");
        System.clearProperty("LOG_PATH");
        Log4jConfigurer.initLogging("classpath:log4j.properties");
    }

    @Test
    public void loadDefaultResource() {

        Mockito.when(context.getResource(ArgumentMatchers.contains("${APPLICATION_CONFIG_URL}"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));

    }

    @Test
    public void loadSessionEventPublisher() {

        Mockito.when(context.getResource(ArgumentMatchers.contains("${APPLICATION_CONFIG_URL}"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        ArgumentCaptor<HttpSessionEventPublisher> httpSessionEventPublisherArgumentCaptor = ArgumentCaptor.forClass(HttpSessionEventPublisher.class);
        verify(servletContext, atLeastOnce()).addListener(httpSessionEventPublisherArgumentCaptor.capture());
        assertNotNull(httpSessionEventPublisherArgumentCaptor.getValue());
    }

    @Test
    public void activeProfiles() {

        System.setProperty("spring.profiles.active", "foo");

        Mockito.when(context.getResource(ArgumentMatchers.anyString())).thenReturn(
                new ByteArrayResource("spring_profiles: bar".getBytes()));

        initializer.initialize(context);

        assertEquals("bar", environment.getActiveProfiles()[0]);
    }

    @Test
    public void activeProfilesFromYaml() {

        Mockito.when(context.getResource(ArgumentMatchers.anyString())).thenReturn(
                new ByteArrayResource("spring_profiles: bar".getBytes()));

        initializer.initialize(context);

        assertEquals("bar", environment.getActiveProfiles()[0]);
    }

    @Test
    public void log4jFileFromYaml() {
        Mockito.when(context.getResource(ArgumentMatchers.anyString())).thenReturn(
                new ByteArrayResource("logging:\n  file: /tmp/bar.log".getBytes()));
        initializer.initialize(context);
        assertEquals("/tmp/bar.log", System.getProperty("LOG_FILE"));
    }

    @Test
    public void log4jPathFromYaml() {
        Mockito.when(context.getResource(ArgumentMatchers.anyString())).thenReturn(
                new ByteArrayResource("logging:\n  path: /tmp/log/bar".getBytes()));
        initializer.initialize(context);
        assertEquals("/tmp/log/bar", System.getProperty("LOG_PATH"));
    }

    @Test
    public void log4jConfigurationFromYaml() {
        Mockito.when(context.getResource(ArgumentMatchers.anyString())).thenReturn(
                new ByteArrayResource("logging:\n  config: bar".getBytes()));
        initializer.initialize(context);
    }

    @Test
    public void loadServletConfiguredFilename() {

        Mockito.when(servletConfig.getInitParameter("APPLICATION_CONFIG_FILE")).thenReturn("/config/path/foo.yml");
        Mockito.when(context.getResource(ArgumentMatchers.eq("file:/config/path/foo.yml"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    public void loadServletConfiguredResource() {

        Mockito.when(servletConfig.getInitParameter("environmentConfigLocations")).thenReturn("foo.yml");
        Mockito.when(context.getResource(ArgumentMatchers.eq("foo.yml"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    public void loadContextConfiguredResource() {

        Mockito.when(servletContext.getInitParameter("environmentConfigLocations")).thenReturn("foo.yml");
        Mockito.when(context.getResource(ArgumentMatchers.eq("foo.yml"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    public void loadReplacedResource() {

        System.setProperty("APPLICATION_CONFIG_URL", "file:foo/uaa.yml");

        Mockito.when(context.getResource(ArgumentMatchers.eq("file:foo/uaa.yml"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    public void loadReplacedResourceFromFileLocation() {

        System.setProperty("APPLICATION_CONFIG_FILE", "foo/uaa.yml");

        Mockito.when(context.getResource(ArgumentMatchers.eq("file:foo/uaa.yml"))).thenReturn(
                new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

        initializer.initialize(context);

        assertEquals("bar", environment.getProperty("foo"));
        assertEquals("baz", environment.getProperty("spam.foo"));
    }

    @Test
    public void loggingConfigVariableWorks() {
        System.setProperty("APPLICATION_CONFIG_FILE", "foo/uaa.yml");
        Mockito.when(context.getResource(ArgumentMatchers.eq("file:foo/uaa.yml"))).thenReturn(
                new ByteArrayResource("logging:\n  config: /some/path".getBytes()));
        initializer.initialize(context);
        assertEquals("/some/path", environment.getProperty("logging.config"));
        assertNull(environment.getProperty("smtp.host"));
        assertNull(environment.getProperty("smtp.port"));
    }

    @Test
    public void readingYamlFromEnvironment_WithNullVariableName() {
        readingYamlFromEnvironment(null);
    }

    @Test
    public void readingYamlFromEnvironment_WithNonNullVariableName() {
        readingYamlFromEnvironment("Renaming environment variable");
    }

    private void readingYamlFromEnvironment(String variableName) {
        if (hasText(variableName)) {
            initializer.setYamlEnvironmentVariableName(variableName);
        }
        SystemEnvironmentAccessor env = new SystemEnvironmentAccessor() {
            @Override
            public String getEnvironmentVariable(String name) {
                return name.equals(initializer.getYamlEnvironmentVariableName()) ?
                        "uaa.url: http://uaa.test.url/\n" +
                                "login.url: http://login.test.url/\n" +
                                "smtp:\n" +
                                "  host: mail.server.host\n" +
                                "  port: 3535\n" :
                        null;
            }
        };
        initializer.setEnvironmentAccessor(env);
        initializer.initialize(context);
        assertEquals("mail.server.host", environment.getProperty("smtp.host"));
        assertEquals("3535", environment.getProperty("smtp.port"));
        assertEquals("http://uaa.test.url/", environment.getProperty("uaa.url"));
        assertEquals("http://login.test.url/", environment.getProperty("login.url"));
    }

    @Test
    public void ignoreDashDTomcatLoggingConfigVariable() {
        final String tomcatLogConfig = "-Djava.util.logging.config=/some/path/logging.properties";
        System.setProperty("APPLICATION_CONFIG_FILE", "foo/uaa.yml");
        ArgumentCaptor<String> servletLogCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.when(context.getResource(ArgumentMatchers.eq("file:foo/uaa.yml"))).thenReturn(
                new ByteArrayResource(("logging:\n  config: " + tomcatLogConfig).getBytes()));
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
        assertEquals("-Djava.util.logging.config=/some/path/logging.properties", environment.getProperty("logging.config"));
        Mockito.verify(servletContext, atLeastOnce()).log(servletLogCaptor.capture());
        boolean logEntryFound = false;
        for (String s : servletLogCaptor.getAllValues()) {
            if (s.startsWith("Ignoring Log Config Location") && s.contains("Tomcat startup script environment variable")) {
                logEntryFound = true;
            }
        }
        assertTrue("Expected to find a log entry indicating that the LOGGING_CONFIG variable was found.", logEntryFound);
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
}
