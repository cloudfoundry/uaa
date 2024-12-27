/*
 * *****************************************************************************
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

import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

/**
 * Factory for Properties that reads from the Spring context {@link Environment}
 * where it can.
 * 
 * @author Dave Syer
 * 
 */
public class EnvironmentPropertiesFactoryBean implements FactoryBean<Properties>, EnvironmentAware {

    private Environment environment;

    private final Map<String, Object> defaultProperties = new HashMap<>();

    public void setDefaultProperties(Properties defaultProperties) {
        this.defaultProperties.clear();
        for (Object key : defaultProperties.keySet()) {
            this.defaultProperties.put((String) key, defaultProperties.get(key));
        }
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public Properties getObject() {

        Properties result = new Properties();
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setEnvironment(environment);
        factory.setDefaultProperties(defaultProperties);
        Map<String, ?> map = Optional.ofNullable(factory.getObject()).orElse(Collections.emptyMap());
        for (Object key : map.keySet()) {
            Object value = map.get(key);
            if (value == null) {
                value = "";
            }
            result.put(key, value);
        }

        return result;

    }

    @Override
    public Class<?> getObjectType() {
        return Properties.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }

}
