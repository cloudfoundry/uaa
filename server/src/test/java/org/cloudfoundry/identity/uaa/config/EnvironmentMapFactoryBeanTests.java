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
package org.cloudfoundry.identity.uaa.config;

import static org.junit.Assert.assertEquals;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.cloudfoundry.identity.uaa.impl.config.EnvironmentMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.junit.Test;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 * 
 */
public class EnvironmentMapFactoryBeanTests {

    @Test
    public void testDefaultProperties() throws Exception {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("foo=foo"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("foo", properties.get("foo"));
    }

    @Test
    public void testRawPlaceholderProperties() throws Exception {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("foo=${bar}"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("${bar}", properties.get("foo"));
    }

    @Test
    public void testPlaceholderProperties() throws Exception {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addLast(new NestedMapPropertySource("override", getProperties("bar=${spam}")));
        factory.setEnvironment(environment);
        factory.setDefaultProperties(getProperties("foo=baz"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("baz", properties.get("foo"));
        assertEquals("${spam}", properties.get("bar"));
    }

    @Test
    public void testOverrideProperties() throws Exception {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("foo=foo"));
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addLast(new NestedMapPropertySource("override", getProperties("foo=bar")));
        factory.setEnvironment(environment);
        Map<String, ?> properties = factory.getObject();
        assertEquals("bar", properties.get("foo"));
    }

    private Map<String, ?> getProperties(String input) {
        HashMap<String, Object> result = new HashMap<String, Object>();
        Properties properties = StringUtils.splitArrayElementsIntoProperties(
                        StringUtils.commaDelimitedListToStringArray(input), "=");
        for (Enumeration<?> keys = properties.propertyNames(); keys.hasMoreElements();) {
            String key = (String) keys.nextElement();
            result.put(key, properties.getProperty(key));
        }
        return result;
    }

}
