package org.cloudfoundry.identity.uaa.impl.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.cloudfoundry.identity.uaa.util.UaaYamlUtils;
import org.slf4j.MDC;
import org.springframework.beans.factory.config.YamlMapFactoryBean;
import org.springframework.beans.factory.config.YamlProcessor;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.util.InMemoryResource;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.SystemPropertyUtils;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.commaDelimitedListToStringArray;
import static org.springframework.util.StringUtils.hasLength;
import static org.springframework.util.StringUtils.hasText;

/**
 * An {@link ApplicationContextInitializer} for a web application to enable it
 * to externalize the environment and logging configuration.
 *
 * <p>A YAML config file is loaded if present and inserted into the environment.
 *
 * <p>In addition if the YAML contains some special properties, some initialization is carried out:
 *
 * <ul>
 * <li><code>spring_profiles</code> - then the active profiles are set</li>
 * <li><code>logging.config</code> - then log4j is initialized from that
 * location (if it exists)</li>
 * </ul>
 */
public class YamlServletProfileInitializer implements ApplicationContextInitializer<ConfigurableWebApplicationContext> {

    private static final String DEFAULT_YAML_KEY = "environmentYamlKey";

    static final String YML_ENV_VAR_NAME = "UAA_CONFIG_YAML";

    private SystemEnvironmentAccessor environmentAccessor = new SystemEnvironmentAccessor() {
    };

    private static final List<String> FILE_CONFIG_LOCATIONS;
    private static final String SECRETS_DIR_VAR = "${SECRETS_DIR}";

    static {
        FILE_CONFIG_LOCATIONS = List.of(
                "${LOGIN_CONFIG_URL}",
                "file:${LOGIN_CONFIG_PATH}/login.yml",
                "file:${CLOUDFOUNDRY_CONFIG_PATH}/login.yml",
                "${UAA_CONFIG_URL}",
                "file:${UAA_CONFIG_FILE}",
                "file:${UAA_CONFIG_PATH}/uaa.yml",
                "file:${CLOUDFOUNDRY_CONFIG_PATH}/uaa.yml"
        );
    }

    @Override
    public void initialize(ConfigurableWebApplicationContext applicationContext) {

        ServletContext servletContext = applicationContext.getServletContext();
        final String contextPath = servletContext != null ? servletContext.getContextPath() : "/";

        JacksonObjectMapperConfig.configureJsonPathForJackson();

        ServletConfig servletConfig = null;
        try {
            servletConfig = applicationContext.getServletConfig();
        } catch (UnsupportedOperationException ignore) {
            System.err.println("Unable to load Servlet Context - are you testing?");
        }
        WebApplicationContextUtils.initServletPropertySources(applicationContext.getEnvironment().getPropertySources(),
                servletContext, servletConfig);

        List<Resource> resources = new ArrayList<>();

        // add default locations first
        Stream.of("uaa.yml", "login.yml")
                .map(ClassPathResource::new)
                .filter(ClassPathResource::exists)
                .forEach(resources::add);

        resources.addAll(getResource(applicationContext, FILE_CONFIG_LOCATIONS));
        resources.addAll(getResource(applicationContext, getSecretsFiles(applicationContext)));

        Resource yamlFromEnv = getYamlFromEnvironmentVariable();
        if (yamlFromEnv != null) {
            resources.add(yamlFromEnv);
        }

        try {
            System.out.println("Loading YAML environment properties from location: " + resources.toString());
            YamlMapFactoryBean factory = new YamlMapFactoryBean();
            factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);

            factory.setResources(resources.toArray(new Resource[0]));

            Map<String, Object> map = Optional.ofNullable(factory.getObject()).orElse(Collections.emptyMap());
            String yamlStr = UaaYamlUtils.dump(map);
            map.put(DEFAULT_YAML_KEY, yamlStr);
            NestedMapPropertySource properties = new NestedMapPropertySource("servletConfigYaml", map);
            applicationContext.getEnvironment().getPropertySources().addLast(properties);
            applySpringProfiles(applicationContext.getEnvironment());
            applyLog4jConfiguration(applicationContext.getEnvironment(), contextPath);

        } catch (Exception e) {
            System.err.println("Error loading YAML environment properties from location: " + resources.toString());
            e.printStackTrace();
        }
    }

    private static List<String> getSecretsFiles(
            final ConfigurableWebApplicationContext applicationContext
    ) {
        final String resolvedSecretsLocation = applicationContext
                .getEnvironment()
                .resolvePlaceholders(SECRETS_DIR_VAR);

        System.out.println(SECRETS_DIR_VAR + " resolves to " + resolvedSecretsLocation);

        final File[] secretFiles =
                ofNullable(new File(resolvedSecretsLocation).listFiles((dir, name) -> name != null && name.endsWith(".yml")))
                        .orElse(new File[]{});

        if (secretFiles.length == 0) {
            System.out.println("Found no .yml files in " + SECRETS_DIR_VAR);
        }

        return Arrays.stream(secretFiles)
                .map(File::getAbsolutePath)
                .map("file:%s"::formatted)
                .toList();
    }

    private Resource getYamlFromEnvironmentVariable() {
        if (environmentAccessor != null) {
            String data = environmentAccessor.getEnvironmentVariable(YML_ENV_VAR_NAME);
            if (hasText(data)) {
                //validate the Yaml? We don't do that for the others
                return new InMemoryResource(data);
            }
        }
        return null;
    }

    private static List<Resource> getResource(
            final ConfigurableWebApplicationContext applicationContext,
            final List<String> fileConfigLocations
    ) {
        final List<String> resolvedLocations = fileConfigLocations.stream()
                .map(applicationContext.getEnvironment()::resolvePlaceholders)
                .toList();

        resolvedLocations.stream()
                .map("Testing for YAML resources at: %s"::formatted)
                .forEach(System.out::println);

        return resolvedLocations.stream()
                .map(applicationContext::getResource)
                .filter(Objects::nonNull)
                .filter(Resource::exists)
                .toList();
    }

    private void applyLog4jConfiguration(ConfigurableEnvironment environment, String contextPath) {
        String log4jConfigLocation = "classpath:log4j2.properties";

        if (environment.containsProperty("logging.config")) {
            //tomcat sets the LOGGING_CONFIG environment variable,
            //we do not want that variable
            //this variable starts with -D, so we can ignore it.
            String location = environment.getProperty("logging.config");
            if (location != null && !location.trim().isEmpty()) {
                PropertySource<?> environmentPropertySource = environment.getPropertySources().get(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
                if (location.startsWith("-D") && environmentPropertySource != null && location.equals(environmentPropertySource.getProperty("LOGGING_CONFIG"))) {
                    System.out.println("Ignoring Log Config Location: " + location + ". Location is suspect to be a Tomcat startup script environment variable");
                } else {
                    System.out.println("Setting Log Config Location: " + location + " based on logging.config setting.");
                    log4jConfigLocation = environment.getProperty("logging.config");
                }
            }
        }

        System.out.println("Loading log4j config from location: " + log4jConfigLocation);
        try {
            String resolvedLocation = SystemPropertyUtils.resolvePlaceholders(log4jConfigLocation);
            URL url = ResourceUtils.getURL(resolvedLocation);
            if (ResourceUtils.URL_PROTOCOL_FILE.equals(url.getProtocol()) && !ResourceUtils.getFile(url).exists()) {
                throw new FileNotFoundException("Log4j config file [" + resolvedLocation + "] not found");
            }

            LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
            loggerContext.setConfigLocation(ResourceUtils.toURI(url));

        } catch (FileNotFoundException | URISyntaxException e) {
            System.err.println("Error loading log4j config from location: " + log4jConfigLocation);
            e.printStackTrace();
        }
        MDC.put("context", contextPath); // used to fill in %X{context} in our `property.log_pattern` log format
    }

    static void applySpringProfiles(ConfigurableEnvironment environment) {
        environment.setDefaultProfiles(new String[0]);

        System.out.printf("System property spring.profiles.active=[%s]%n", System.getProperty("spring.profiles.active"));
        System.out.printf("Environment property spring_profiles=[%s]%n", environment.getProperty("spring_profiles"));

        if (environment.containsProperty("spring_profiles")) {
            setActiveProfiles(environment, StringUtils.tokenizeToStringArray(environment.getProperty("spring_profiles"), ",", true, true));
            return;
        }

        String systemProfiles = System.getProperty("spring.profiles.active");
        if (hasLength(systemProfiles)) {
            setActiveProfiles(environment, commaDelimitedListToStringArray(systemProfiles));
            return;
        }

        setActiveProfiles(environment, new String[]{"hsqldb"});
    }

    private static void setActiveProfiles(
            final ConfigurableEnvironment environment,
            final String[] profiles) {
        System.out.println("Setting active profiles: " + Arrays.toString(profiles));
        environment.setActiveProfiles(profiles);
    }

    void setEnvironmentAccessor(SystemEnvironmentAccessor environmentAccessor) {
        this.environmentAccessor = environmentAccessor;
    }
}
