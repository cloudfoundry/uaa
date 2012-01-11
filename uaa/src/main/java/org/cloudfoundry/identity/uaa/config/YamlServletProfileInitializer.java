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
package org.cloudfoundry.identity.uaa.config;

import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ConfigurableWebApplicationContext;

/**
 * @author Dave Syer
 * 
 */
public class YamlServletProfileInitializer implements ApplicationContextInitializer<ConfigurableWebApplicationContext> {

	private final static Log logger = LogFactory.getLog(YamlServletProfileInitializer.class);

	private static final String PROFILE_CONFIG_FILE_LOCATION = "environmentConfigFile";

	private static final String DEFAULT_PROFILE_CONFIG_FILE_LOCATION = "file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml";

	@Override
	public void initialize(ConfigurableWebApplicationContext applicationContext) {
		String location = applicationContext.getServletConfig().getInitParameter(PROFILE_CONFIG_FILE_LOCATION);
		location = location == null ? DEFAULT_PROFILE_CONFIG_FILE_LOCATION : location;
		location = applicationContext.getEnvironment().resolvePlaceholders(location);
		Resource resource = applicationContext.getResource(location);
		if (resource == null || !resource.exists()) {
			logger.debug("No YAML environment properties found at location: " + location);
			return;
		}

		try {
			logger.debug("Loading YAML environment properties from location: " + location);
			YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
			factory.setIgnoreResourceNotFound(true);
			factory.setResource(resource);
			Properties properties = factory.getObject();
			if (properties.containsKey("spring_profiles")) {
				applicationContext.getEnvironment().setActiveProfiles(
						StringUtils.commaDelimitedListToStringArray(properties.getProperty("spring_profiles")));
			}
			applicationContext.getEnvironment().getPropertySources()
					.addLast(new PropertiesPropertySource("servletConfigYaml", properties));
		}
		catch (Exception e) {
			logger.error("Error loading YAML environment properties from location: " + location, e);
		}

	}

}
