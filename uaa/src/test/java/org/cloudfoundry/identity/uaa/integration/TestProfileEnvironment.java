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
package org.cloudfoundry.identity.uaa.integration;

import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.config.YamlPropertiesFactoryBean;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;

/**
 * @author Dave Syer
 * 
 */
public class TestProfileEnvironment {

	private static final Log logger = LogFactory.getLog(TestProfileEnvironment.class);

	private StandardEnvironment environment = new StandardEnvironment();

	static TestProfileEnvironment instance = new TestProfileEnvironment();

	private TestProfileEnvironment() {
		String location = null;
		try {
			location = environment.resolveRequiredPlaceholders("${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml");
		}
		catch (IllegalArgumentException e) {
			logger.debug("No config at CLOUD_FOUNDRY_CONFIG_PATH="
					+ environment.getProperty("CLOUD_FOUNDRY_CONFIG_PATH"));
		}
		if (location != null) {
			YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
			factory.setResource(new FileSystemResource(location));
			factory.setIgnoreResourceNotFound(true);
			Properties properties = factory.getObject();
			logger.debug("Environment properties: " + properties);
			if (!properties.isEmpty()) {
				if (properties.containsKey("spring_profiles")) {
					properties.setProperty(StandardEnvironment.ACTIVE_PROFILES_PROPERTY_NAME,
							properties.getProperty("spring_profiles"));
				}
				// System properties should override the ones in the config file, so add it last
				environment.getPropertySources().addLast(new PropertiesPropertySource("uaa.yml", properties));
			}
		}
	}
	
	/**
	 * @return the environment
	 */
	public static Environment getEnvironment() {
		return instance.environment;
	}

}
