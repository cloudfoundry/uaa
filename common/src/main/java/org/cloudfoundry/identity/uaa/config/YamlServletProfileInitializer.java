/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.config;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;

import org.apache.log4j.MDC;
import org.cloudfoundry.identity.uaa.config.YamlProcessor.ResolutionMethod;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.Log4jConfigurer;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.yaml.snakeyaml.Yaml;

/**
 * An {@link ApplicationContextInitializer} for a web application to enable it to externalize the environment and
 * logging configuration. A YAML config file is loaded if present and inserted into the environment. In addition if the
 * YAML contains some special properties, some initialization is carried out:
 *
 * <ul>
 * <li><code>spring_profiles</code> - then the active profiles are set</li>
 * <li><code>logging.config</code> - then log4j is initialized from that location (if it exists)</li>
 * </ul>
 *
 * @author Dave Syer
 *
 */
public class YamlServletProfileInitializer implements ApplicationContextInitializer<ConfigurableWebApplicationContext> {

	private static final String PROFILE_CONFIG_FILE_LOCATIONS = "environmentConfigLocations";

	private static final String PROFILE_CONFIG_FILE_DEFAULT = "environmentConfigDefaults";

	public static final String[] DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS = new String[] { "${APPLICATION_CONFIG_URL}",
			"file:${APPLICATION_CONFIG_FILE}" };

	private static final String DEFAULT_YAML_KEY = "environmentYamlKey";

	private String rawYamlKey = DEFAULT_YAML_KEY;

	@Override
	public void initialize(ConfigurableWebApplicationContext applicationContext) {

		Resource resource = null;
		ServletContext servletContext = applicationContext.getServletContext();
		WebApplicationContextUtils.initServletPropertySources(applicationContext.getEnvironment().getPropertySources(),
				servletContext, applicationContext.getServletConfig());

		ServletConfig servletConfig = applicationContext.getServletConfig();
		String locations = servletConfig == null ? null : servletConfig.getInitParameter(PROFILE_CONFIG_FILE_LOCATIONS);
		resource = getResource(servletContext, applicationContext, locations);

		if (resource == null) {
			servletContext.log("No YAML environment properties from servlet.  Defaulting to servlet context.");
			locations = servletContext.getInitParameter(PROFILE_CONFIG_FILE_LOCATIONS);
			resource = getResource(servletContext, applicationContext, locations);
		}

		try {
			servletContext.log("Loading YAML environment properties from location: " + resource);
			YamlMapFactoryBean factory = new YamlMapFactoryBean();
			factory.setResolutionMethod(ResolutionMethod.OVERRIDE_AND_IGNORE);

			List<Resource> resources = new ArrayList<Resource>();

			String defaultLocation = servletConfig == null ? null : servletConfig.getInitParameter(PROFILE_CONFIG_FILE_DEFAULT);
			if (defaultLocation!=null) {
				Resource defaultResource = new ClassPathResource(defaultLocation);
				if (defaultResource.exists()) {
					resources.add(defaultResource);
				}
			}

			resources.add(resource);
			factory.setResources(resources.toArray(new Resource[resources.size()]));

			Map<String, Object> map = factory.getObject();
			String yamlStr = (new Yaml()).dump(map);
			map.put(rawYamlKey, yamlStr);
			NestedMapPropertySource properties = new NestedMapPropertySource("servletConfigYaml", map);
			applicationContext.getEnvironment().getPropertySources().addLast(properties);
			applySpringProfiles(applicationContext.getEnvironment(), servletContext);
			applyLog4jConfiguration(applicationContext.getEnvironment(), servletContext);

		}
		catch (Exception e) {
			servletContext.log("Error loading YAML environment properties from location: " + resource, e);
		}

	}

	private Resource getResource(ServletContext servletContext, ConfigurableWebApplicationContext applicationContext,
			String locations) {
		Resource resource = null;
		String[] configFileLocations = locations == null ? DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS : StringUtils
				.commaDelimitedListToStringArray(locations);
		for (String location : configFileLocations) {
			location = applicationContext.getEnvironment().resolvePlaceholders(location);
			servletContext.log("Testing for YAML resources at: " + location);
			resource = applicationContext.getResource(location);
			if (resource != null && resource.exists()) {
				break;
			}
		}
		return resource;
	}

	private void applyLog4jConfiguration(ConfigurableEnvironment environment, ServletContext servletContext) {

		String log4jConfigLocation = "classpath:log4j.properties";

		if (environment.containsProperty("logging.file")) {
			String location = environment.getProperty("logging.file");
			servletContext.log("Setting LOG_FILE: " + location);
			System.setProperty("LOG_FILE", location);
		}

		else if (environment.containsProperty("logging.path")) {
			String location = environment.getProperty("logging.path");
			servletContext.log("Setting LOG_PATH: " + location);
			System.setProperty("LOG_PATH", location);
		}

		else if (environment.containsProperty("logging.config")) {
			log4jConfigLocation = environment.getProperty("logging.config");
		}

		try {
			servletContext.log("Loading log4j config from location: " + log4jConfigLocation);
			Log4jConfigurer.initLogging(log4jConfigLocation);
		}
		catch (FileNotFoundException e) {
			servletContext.log("Error loading log4j config from location: " + log4jConfigLocation, e);
		}

		MDC.put("context", servletContext.getContextPath());

	}

	private void applySpringProfiles(ConfigurableEnvironment environment, ServletContext servletContext) {
		if (environment.containsProperty("spring_profiles")) {
			String profiles = (String) environment.getProperty("spring_profiles");
			servletContext.log("Setting active profiles: " + profiles);
			environment.setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
		}
	}

}
