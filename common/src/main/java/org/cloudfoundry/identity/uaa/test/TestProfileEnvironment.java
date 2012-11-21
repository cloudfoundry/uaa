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
package org.cloudfoundry.identity.uaa.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.config.EnvironmentPropertiesFactoryBean;
import org.cloudfoundry.identity.uaa.config.YamlProcessor.ResolutionMethod;
import org.cloudfoundry.identity.uaa.config.YamlPropertiesFactoryBean;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

/**
 * @author Dave Syer
 * 
 */
public class TestProfileEnvironment {

	private static final Log logger = LogFactory.getLog(TestProfileEnvironment.class);

	private static final String[] DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS = new String[] { "classpath:uaa.yml",
			"file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml", "file:${UAA_CONFIG_FILE}", "${UAA_CONFIG_URL}" };

	private StandardEnvironment environment = new StandardEnvironment();

	private static TestProfileEnvironment instance = new TestProfileEnvironment();

	private ResourceLoader recourceLoader = new DefaultResourceLoader();

	private TestProfileEnvironment() {

		List<Resource> resources = new ArrayList<Resource>();

		for (String location : DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS) {
			location = environment.resolvePlaceholders(location);
			Resource resource = recourceLoader.getResource(location);
			if (resource != null && resource.exists()) {
				resources.add(resource);
			}
		}

		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(resources.toArray(new Resource[resources.size()]));
		factory.setDocumentMatchers(Collections.singletonMap("platform",
				environment.acceptsProfiles("postgresql") ? "postgresql" : "hsqldb"));
		factory.setResolutionMethod(ResolutionMethod.OVERRIDE_AND_IGNORE);
		Properties properties = factory.getObject();

		logger.debug("Decoding environment properties: " + properties.size());
		if (!properties.isEmpty()) {
			for (Enumeration<?> names = properties.propertyNames(); names.hasMoreElements();) {
				String name = (String) names.nextElement();
				String value = properties.getProperty(name);
				if (value != null) {
					properties.setProperty(name, environment.resolvePlaceholders(value));
				}
			}
			if (properties.containsKey("spring_profiles")) {
				properties.setProperty(StandardEnvironment.ACTIVE_PROFILES_PROPERTY_NAME,
						properties.getProperty("spring_profiles"));
			}
			// System properties should override the ones in the config file, so add it last
			environment.getPropertySources().addLast(new PropertiesPropertySource("uaa.yml", properties));
		}

		EnvironmentPropertiesFactoryBean environmentProperties = new EnvironmentPropertiesFactoryBean();
		environmentProperties.setEnvironment(environment);
		environmentProperties.setDefaultProperties(properties);
		Map<String, ?> debugProperties = environmentProperties.getObject();
		logger.debug("Environment properties: " + debugProperties);
	}

	/**
	 * @return the environment
	 */
	public static ConfigurableEnvironment getEnvironment() {
		return instance.environment;
	}

}
