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
package org.cloudfoundry.identity.uaa.test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.impl.config.EnvironmentMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor.ResolutionMethod;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

/**
 * @author Dave Syer
 * 
 */
public class TestProfileEnvironment {

    private static final Logger logger = LoggerFactory.getLogger(TestProfileEnvironment.class);

    private static final String[] DEFAULT_PROFILE_CONFIG_FILE_LOCATIONS = new String[] { "classpath:uaa.yml",
                    "file:${CLOUDFOUNDRY_CONFIG_PATH}/uaa.yml", "file:${UAA_CONFIG_FILE}", "${UAA_CONFIG_URL}" };

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

        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResources(resources.toArray(new Resource[0]));
        factory.setResolutionMethod(ResolutionMethod.OVERRIDE_AND_IGNORE);
        Map<String, Object> properties = factory.getObject();

        logger.debug("Decoding environment properties: " + properties.size());
        if (!properties.isEmpty()) {
            for (String name : properties.keySet()) {
                Object value = properties.get(name);
                if (value instanceof String) {
                    properties.put(name, environment.resolvePlaceholders((String) value));
                }
            }
            if (properties.containsKey("spring_profiles")) {
                properties.put(AbstractEnvironment.ACTIVE_PROFILES_PROPERTY_NAME, properties.get("spring_profiles"));
            }
            // System properties should override the ones in the config file, so
            // add it last
            environment.getPropertySources().addLast(new NestedMapPropertySource("uaa.yml", properties));
        }

        EnvironmentMapFactoryBean environmentProperties = new EnvironmentMapFactoryBean();
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
