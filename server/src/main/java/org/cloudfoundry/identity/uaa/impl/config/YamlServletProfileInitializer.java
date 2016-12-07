/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.impl.config;

import org.apache.log4j.MDC;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor.ResolutionMethod;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.util.InMemoryResource;
import org.springframework.util.Log4jConfigurer;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.yaml.snakeyaml.Yaml;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import java.io.FileNotFoundException;
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
 *
 *
 *
 */
public class YamlServletProfileInitializer implements ApplicationContextInitializer<ConfigurableWebApplicationContext> {

    private static final String PROFILE_CONFIG_FILE_LOCATIONS = "environmentConfigLocations";

    private static final String PROFILE_CONFIG_FILE_DEFAULT = "environmentConfigDefaults";

    public static final String[] DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS = new String[] { "${APPLICATION_CONFIG_URL}",
                    "file:${APPLICATION_CONFIG_FILE}" };

    private static final String DEFAULT_YAML_KEY = "environmentYamlKey";

    private String rawYamlKey = DEFAULT_YAML_KEY;

    private String yamlEnvironmentVariableName = "UAA_CONFIG_YAML";

    private SystemEnvironmentAccessor environmentAccessor = new SystemEnvironmentAccessor(){};

    @Override
    public void initialize(ConfigurableWebApplicationContext applicationContext) {

        ServletContext servletContext = applicationContext.getServletContext();
        WebApplicationContextUtils.initServletPropertySources(applicationContext.getEnvironment().getPropertySources(),
                        servletContext, applicationContext.getServletConfig());

        ServletConfig servletConfig = applicationContext.getServletConfig();
        String locations = servletConfig == null ? null : servletConfig.getInitParameter(PROFILE_CONFIG_FILE_LOCATIONS);
        List<Resource> resources = new ArrayList<>();

        //add default locations first
        Set<String> defaultLocation = StringUtils.commaDelimitedListToSet(servletConfig == null ? null : servletConfig.getInitParameter(PROFILE_CONFIG_FILE_DEFAULT));
        if (defaultLocation != null && defaultLocation.size()>0) {
            for (String s : defaultLocation) {
                Resource defaultResource = new ClassPathResource(s);
                if (defaultResource.exists()) {
                    resources.add(defaultResource);
                }
            }
        }


        resources.addAll(getResource(servletContext, applicationContext, locations));

        Resource yamlFromEnv = getYamlFromEnvironmentVariable();
        if (yamlFromEnv!=null) {
            resources.add(yamlFromEnv);
        }

        if (resources.isEmpty()) {
            servletContext.log("No YAML environment properties from servlet.  Defaulting to servlet context.");
            locations = servletContext.getInitParameter(PROFILE_CONFIG_FILE_LOCATIONS);
            resources.addAll(getResource(servletContext, applicationContext, locations));
        }

        try {
            servletContext.log("Loading YAML environment properties from location: " + resources.toString());
            YamlMapFactoryBean factory = new YamlMapFactoryBean();
            factory.setResolutionMethod(ResolutionMethod.OVERRIDE_AND_IGNORE);

            factory.setResources(resources.toArray(new Resource[resources.size()]));

            Map<String, Object> map = factory.getObject();
            String yamlStr = (new Yaml()).dump(map);
            map.put(rawYamlKey, yamlStr);
            NestedMapPropertySource properties = new NestedMapPropertySource("servletConfigYaml", map);
            applicationContext.getEnvironment().getPropertySources().addLast(properties);
            applySpringProfiles(applicationContext.getEnvironment(), servletContext);
            applyLog4jConfiguration(applicationContext.getEnvironment(), servletContext);

        } catch (Exception e) {
            servletContext.log("Error loading YAML environment properties from location: " + resources.toString(), e);
        }

    }

    protected Resource getYamlFromEnvironmentVariable() {
        if (getEnvironmentAccessor()!=null){
            String data = getEnvironmentAccessor().getEnvironmentVariable(getYamlEnvironmentVariableName());
            if (hasText(data)) {
                //validate the Yaml? We don't do that for the others
                return new InMemoryResource(data);
            }
        }
        return null;
    }

    private List<Resource> getResource(ServletContext servletContext, ConfigurableWebApplicationContext applicationContext,
                    String locations) {
        List<Resource> resources = new LinkedList<>();
        String[] configFileLocations = locations == null ? DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS : StringUtils
                        .commaDelimitedListToStringArray(locations);
        for (String location : configFileLocations) {
            location = applicationContext.getEnvironment().resolvePlaceholders(location);
            servletContext.log("Testing for YAML resources at: " + location);
            Resource resource = applicationContext.getResource(location);
            if (resource != null && resource.exists()) {
                resources.add(resource);
            }
        }
        return resources;
    }

    private void applyLog4jConfiguration(ConfigurableEnvironment environment, ServletContext servletContext) {

        String log4jConfigLocation = "classpath:log4j.properties";

        if (environment.containsProperty("logging.file")) {
            String location = environment.getProperty("logging.file");
            servletContext.log("Setting LOG_FILE: " + location);
            System.setProperty("LOG_FILE", location);
        } else if (environment.containsProperty("logging.path")) {
            String location = environment.getProperty("logging.path");
            servletContext.log("Setting LOG_PATH: " + location);
            System.setProperty("LOG_PATH", location);
        } else if (environment.containsProperty("logging.config")) {
            //tomcat sets the LOGGING_CONFIG environment variable,
            //we do not want that variable
            //this variable starts with -D, so we can ignore it.
            String location = environment.getProperty("logging.config");
            if (location!=null && location.trim().length()>0) {
                PropertySource<?> environmentPropertySource = environment.getPropertySources().get(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
                if ((location.startsWith("-D") && environmentPropertySource!=null && location.equals(environmentPropertySource.getProperty("LOGGING_CONFIG")))) {
                    servletContext.log("Ignoring Log Config Location: " + location + ". Location is suspect to be a Tomcat startup script environment variable");
                } else {
                    servletContext.log("Setting Log Config Location: " + location + " based on logging.config setting.");
                    log4jConfigLocation = environment.getProperty("logging.config");
                }
            }
        }

        try {
            servletContext.log("Loading log4j config from location: " + log4jConfigLocation);
            Log4jConfigurer.initLogging(log4jConfigLocation);
        } catch (FileNotFoundException e) {
            servletContext.log("Error loading log4j config from location: " + log4jConfigLocation, e);
        }

        MDC.put("context", servletContext.getContextPath());

    }

    protected void applySpringProfiles(ConfigurableEnvironment environment, ServletContext servletContext) {
        String systemProfiles = System.getProperty("spring.profiles.active");
        environment.setDefaultProfiles(new String[0]);
        if (environment.containsProperty("spring_profiles")) {
            String profiles = environment.getProperty("spring_profiles");
            servletContext.log("Setting active profiles: " + profiles);
            environment.setActiveProfiles(StringUtils.tokenizeToStringArray(profiles, ",", true, true));
        } else {
            if (isEmpty(systemProfiles)) {
                environment.setActiveProfiles("hsqldb");
            } else {
                environment.setActiveProfiles(commaDelimitedListToStringArray(systemProfiles));
            }
        }
    }

    public String getYamlEnvironmentVariableName() {
        return yamlEnvironmentVariableName;
    }

    public void setYamlEnvironmentVariableName(String yamlEnvironmentVariableName) {
        this.yamlEnvironmentVariableName = yamlEnvironmentVariableName;
    }

    public SystemEnvironmentAccessor getEnvironmentAccessor() {
        return environmentAccessor;
    }

    public void setEnvironmentAccessor(SystemEnvironmentAccessor environmentAccessor) {
        this.environmentAccessor = environmentAccessor;
    }
}
