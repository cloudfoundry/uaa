/**
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

import javax.servlet.ServletContext;

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

	private static final String DEFAULT_PROFILE_CONFIG_FILE_LOCATION = "file:${UAA_CONFIG_FILE}";

	private static final String FALLBACK_PROFILE_CONFIG_FILE_LOCATION = "file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml";

	@Override
	public void initialize(ConfigurableWebApplicationContext applicationContext) {

		String location = applicationContext.getServletConfig().getInitParameter(PROFILE_CONFIG_FILE_LOCATION);
		ServletContext servletContext = applicationContext.getServletContext();
		location = location == null ? DEFAULT_PROFILE_CONFIG_FILE_LOCATION : location;
		location = applicationContext.getEnvironment().resolvePlaceholders(location);
		Resource resource = applicationContext.getResource(location);
		if (resource == null || !resource.exists()) {
			servletContext.log("No YAML environment properties found at location: " + location);
			location = FALLBACK_PROFILE_CONFIG_FILE_LOCATION;
			location = applicationContext.getEnvironment().resolvePlaceholders(location);
			resource = applicationContext.getResource(location);
			if (resource == null || !resource.exists()) {
				servletContext.log("No YAML environment properties found at location: " + location);
				return;
			}
		}

		try {
			servletContext.log("Loading YAML environment properties from location: " + location);
			YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
			factory.setIgnoreResourceNotFound(true);
			factory.setResource(resource);
			Properties properties = factory.getObject();
			applySpringProfiles(properties, applicationContext.getEnvironment(), servletContext);
			applyLog4jConfiguration(properties, applicationContext.getEnvironment(), servletContext);
			applicationContext.getEnvironment().getPropertySources()
					.addLast(new PropertiesPropertySource("servletConfigYaml", properties));
		}
		catch (Exception e) {
			servletContext.log("Error loading YAML environment properties from location: " + location, e);
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
