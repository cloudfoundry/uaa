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
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;

import org.cloudfoundry.identity.uaa.config.YamlProcessor.ResolutionMethod;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.Resource;
import org.springframework.util.Log4jConfigurer;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ConfigurableWebApplicationContext;

/**
 * An {@link ApplicationContextInitializer} for a web application to enable it to externalize the environment and
 * logging configuration. A YAML config file is loaded if present and inserted into the environment. In addition if the
 * YAML contains a property
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

	private static final String PROFILE_CONFIG_FILE_LOCATION = "environmentConfigFile";

	public static final String[] DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS = new String[] { "${UAA_CONFIG_URL}",
			"file:${UAA_CONFIG_FILE}", "file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml" };

	@Override
	public void initialize(ConfigurableWebApplicationContext applicationContext) {

		Resource resource = null;
		ServletContext servletContext = applicationContext.getServletContext();

		for (String location : DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS) {
			location = applicationContext.getEnvironment().resolvePlaceholders(location);
			servletContext.log("Testing for YAML resources at: " + location);
			resource = applicationContext.getResource(location);
			if (resource != null && resource.exists()) {
				break;
			}
		}

		if (resource == null) {
			servletContext.log("No YAML environment properties from environment.  Defaulting to servlet config.");
			ServletConfig servletConfig = applicationContext.getServletConfig();
			if (servletConfig != null) {
				String location = servletConfig.getInitParameter(PROFILE_CONFIG_FILE_LOCATION);
				resource = applicationContext.getResource(location);
			}
		}

		if (resource == null) {
			servletContext.log("No YAML environment properties from servlet.  Defaulting to servlet context.");
			ServletContext servletConfig = applicationContext.getServletContext();
			if (servletConfig != null) {
				String location = servletConfig.getInitParameter(PROFILE_CONFIG_FILE_LOCATION);
				resource = applicationContext.getResource(location);
			}
		}

		try {
			servletContext.log("Loading YAML environment properties from location: " + resource);
			YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
			factory.setResolutionMethod(ResolutionMethod.OVERRIDE_AND_IGNORE);
			factory.setResources(new Resource[] { resource });
			Properties properties = factory.getObject();
			applySpringProfiles(properties, applicationContext.getEnvironment(), servletContext);
			applyLog4jConfiguration(properties, applicationContext.getEnvironment(), servletContext);
			applicationContext.getEnvironment().getPropertySources()
					.addLast(new PropertiesPropertySource("servletConfigYaml", properties));
		}
		catch (Exception e) {
			servletContext.log("Error loading YAML environment properties from location: " + resource, e);
		}

	}

	private void applyLog4jConfiguration(Properties properties, ConfigurableEnvironment environment,
			ServletContext servletContext) {

		String log4jConfigLocation = "classpath:log4j.properties";

		if (properties.containsKey("logging.file")) {
			String location = properties.getProperty("logging.file");
			servletContext.log("Setting LOG_FILE: " + location);
			System.setProperty("LOG_FILE", location);
		}

		else if (properties.containsKey("logging.path")) {
			String location = properties.getProperty("logging.path");
			servletContext.log("Setting LOG_PATH: " + location);
			System.setProperty("LOG_PATH", location);
		}

		else if (properties.containsKey("logging.config")) {
			log4jConfigLocation = properties.getProperty("logging.config");
		}

		try {
			servletContext.log("Loading log4j config from location: " + log4jConfigLocation);
			Log4jConfigurer.initLogging(log4jConfigLocation);
		}
		catch (FileNotFoundException e) {
			servletContext.log("Error loading log4j config from location: " + log4jConfigLocation, e);
		}

	}

	private void applySpringProfiles(Properties properties, ConfigurableEnvironment environment,
			ServletContext servletContext) {
		if (properties.containsKey("spring_profiles")) {
			String profiles = properties.getProperty("spring_profiles");
			servletContext.log("Setting active profiles: " + profiles);
			environment.setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
		}
	}

}
