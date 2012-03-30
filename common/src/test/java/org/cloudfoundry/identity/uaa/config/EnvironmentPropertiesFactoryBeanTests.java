/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.config;

import static org.junit.Assert.assertEquals;

import java.util.Map;
import java.util.Properties;

import org.junit.Test;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 * 
 */
public class EnvironmentPropertiesFactoryBeanTests {

	@Test
	public void testDefaultProperties() throws Exception {
		EnvironmentPropertiesFactoryBean factory = new EnvironmentPropertiesFactoryBean();
		factory.setDefaultProperties(getProperties("foo=foo"));
		Map<String, ?> properties = factory.getObject();
		assertEquals("foo", properties.get("foo"));
	}

	@Test
	public void testOverrideProperties() throws Exception {
		EnvironmentPropertiesFactoryBean factory = new EnvironmentPropertiesFactoryBean();
		factory.setDefaultProperties(getProperties("foo=foo"));
		StandardEnvironment environment = new StandardEnvironment();
		environment.getPropertySources().addLast(new PropertiesPropertySource("override", getProperties("foo=bar")));
		factory.setEnvironment(environment);
		Map<String, ?> properties = factory.getObject();
		assertEquals("bar", properties.get("foo"));
	}

	private Properties getProperties(String input) {
		return StringUtils.splitArrayElementsIntoProperties(StringUtils.commaDelimitedListToStringArray(input), "=");
	}

}
