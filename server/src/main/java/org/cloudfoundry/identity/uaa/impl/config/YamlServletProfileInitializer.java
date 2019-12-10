package org.cloudfoundry.identity.uaa.impl.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor.ResolutionMethod;
import org.slf4j.MDC;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.util.InMemoryResource;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.util.ResourceUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.SystemPropertyUtils;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.yaml.snakeyaml.Yaml;

import javax.servlet.ServletContext;
import java.io.FileNotFoundException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.springframework.util.StringUtils.commaDelimitedListToStringArray;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.util.StringUtils.isEmpty;

/**
 * An {@link ApplicationContextInitializer} for a web application to enable it
 * to externalize the environment and
 * logging configuration. A YAML config file is loaded if present and inserted
 * into the environment. In addition if the
 * YAML contains some special properties, some initialization is carried out:
 *
 * <ul>
 * <li><code>spring_profiles</code> - then the active profiles are set</li>
 * <li><code>logging.config</code> - then log4j is initialized from that
 * location (if it exists)</li>
 * </ul>
 */
public class YamlServletProfileInitializer implements ApplicationContextInitializer<ConfigurableWebApplicationContext> {

    private static final String[] DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS = new String[]{
            "${APPLICATION_CONFIG_URL}",
            "file:${APPLICATION_CONFIG_FILE}"};

    private static final String DEFAULT_YAML_KEY = "environmentYamlKey";

    private String yamlEnvironmentVariableName = "UAA_CONFIG_YAML";

    private SystemEnvironmentAccessor environmentAccessor = new SystemEnvironmentAccessor() {
    };

    @Override
    public void initialize(ConfigurableWebApplicationContext applicationContext) {

        ServletContext servletContext = applicationContext.getServletContext();
        final String contextPath = servletContext != null ? servletContext.getContextPath() : "/";

        if (servletContext != null) {
            HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
            servletContext.addListener(publisher);
        }

        WebApplicationContextUtils.initServletPropertySources(applicationContext.getEnvironment().getPropertySources(),
                servletContext, applicationContext.getServletConfig());

        String locations = "${LOGIN_CONFIG_URL},file:${LOGIN_CONFIG_PATH}/login.yml,file:${CLOUDFOUNDRY_CONFIG_PATH}/login.yml,${UAA_CONFIG_URL},file:${UAA_CONFIG_FILE},file:${UAA_CONFIG_PATH}/uaa.yml,file:${CLOUDFOUNDRY_CONFIG_PATH}/uaa.yml";
        List<Resource> resources = new ArrayList<>();

        //add default locations first
        Set<String> defaultLocation = StringUtils.commaDelimitedListToSet("uaa.yml,login.yml");
        if (defaultLocation != null && defaultLocation.size() > 0) {
            for (String s : defaultLocation) {
                Resource defaultResource = new ClassPathResource(s);
                if (defaultResource.exists()) {
                    resources.add(defaultResource);
                }
            }
        }

        resources.addAll(getResource(applicationContext, locations));

        Resource yamlFromEnv = getYamlFromEnvironmentVariable();
        if (yamlFromEnv != null) {
            resources.add(yamlFromEnv);
        }

        if (resources.isEmpty()) {
            System.out.println("No YAML environment properties from servlet.  Defaulting to servlet context.");
            locations = "${LOGIN_CONFIG_URL},file:${LOGIN_CONFIG_PATH}/login.yml,file:${CLOUDFOUNDRY_CONFIG_PATH}/login.yml,${UAA_CONFIG_URL},file:${UAA_CONFIG_FILE},file:${UAA_CONFIG_PATH}/uaa.yml,file:${CLOUDFOUNDRY_CONFIG_PATH}/uaa.yml";
            resources.addAll(getResource(applicationContext, locations));
        }

        try {
            System.out.println("Loading YAML environment properties from location: " + resources.toString());
            YamlMapFactoryBean factory = new YamlMapFactoryBean();
            factory.setResolutionMethod(ResolutionMethod.OVERRIDE_AND_IGNORE);

            factory.setResources(resources.toArray(new Resource[0]));

            Map<String, Object> map = factory.getObject();
            String yamlStr = (new Yaml()).dump(map);
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

    private Resource getYamlFromEnvironmentVariable() {
        if (environmentAccessor != null) {
            String data = environmentAccessor.getEnvironmentVariable(getYamlEnvironmentVariableName());
            if (hasText(data)) {
                //validate the Yaml? We don't do that for the others
                return new InMemoryResource(data);
            }
        }
        return null;
    }

    private List<Resource> getResource(ConfigurableWebApplicationContext applicationContext,
                                       String locations) {
        List<Resource> resources = new LinkedList<>();
        String[] configFileLocations = locations == null ? DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS : StringUtils
                .commaDelimitedListToStringArray(locations);
        for (String location : configFileLocations) {
            location = applicationContext.getEnvironment().resolvePlaceholders(location);
            System.out.println("Testing for YAML resources at: " + location);
            Resource resource = applicationContext.getResource(location);
            if (resource != null && resource.exists()) {
                resources.add(resource);
            }
        }
        return resources;
    }

    private void applyLog4jConfiguration(ConfigurableEnvironment environment, String contextPath) {
        String log4jConfigLocation = "classpath:log4j2.properties";

        if (environment.containsProperty("logging.config")) {
            //tomcat sets the LOGGING_CONFIG environment variable,
            //we do not want that variable
            //this variable starts with -D, so we can ignore it.
            String location = environment.getProperty("logging.config");
            if (location != null && location.trim().length() > 0) {
                PropertySource<?> environmentPropertySource = environment.getPropertySources().get(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
                if ((location.startsWith("-D") && environmentPropertySource != null && location.equals(environmentPropertySource.getProperty("LOGGING_CONFIG")))) {
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

    void applySpringProfiles(ConfigurableEnvironment environment) {
        String systemProfiles = System.getProperty("spring.profiles.active");
        environment.setDefaultProfiles(new String[0]);
        if (environment.containsProperty("spring_profiles")) {
            String profiles = environment.getProperty("spring_profiles");
            System.out.println("Setting active profiles: " + profiles);
            environment.setActiveProfiles(StringUtils.tokenizeToStringArray(profiles, ",", true, true));
        } else {
            if (isEmpty(systemProfiles)) {
                environment.setActiveProfiles("hsqldb");
            } else {
                environment.setActiveProfiles(commaDelimitedListToStringArray(systemProfiles));
            }
        }
    }

    String getYamlEnvironmentVariableName() {
        return yamlEnvironmentVariableName;
    }

    void setYamlEnvironmentVariableName(String yamlEnvironmentVariableName) {
        this.yamlEnvironmentVariableName = yamlEnvironmentVariableName;
    }

    void setEnvironmentAccessor(SystemEnvironmentAccessor environmentAccessor) {
        this.environmentAccessor = environmentAccessor;
    }
}
