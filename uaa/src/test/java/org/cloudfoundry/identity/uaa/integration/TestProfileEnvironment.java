/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
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
