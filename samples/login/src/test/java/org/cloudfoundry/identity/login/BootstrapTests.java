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
package org.cloudfoundry.identity.login;

import static org.junit.Assert.assertNotNull;

import org.cloudfoundry.identity.uaa.config.YamlPropertiesFactoryBean;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.ViewResolver;

/**
 * @author Dave Syer
 *
 */
public class BootstrapTests {
	
	private GenericXmlApplicationContext context;
	
	@Before
	public void setup() throws Exception {
		System.clearProperty("spring.profiles.active");		
	}
	
	@After
	public void cleanup() throws Exception {
		System.clearProperty("spring.profiles.active");		
		if (context!=null) {
			context.close();
		}
	}

	@Test
	public void testRootContextDefaults() throws Exception {
		context = getServletContext("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
		assertNotNull(context.getBean("viewResolver", ViewResolver.class));
	}

	private GenericXmlApplicationContext getServletContext(String... resources) {
		
		String profiles = null;
		String[] resourcesToLoad = resources;
		if (!resources[0].endsWith(".xml")) {
			profiles = resources[0];
			resourcesToLoad = new String[resources.length-1];
			System.arraycopy(resources, 1, resourcesToLoad, 0, resourcesToLoad.length);
		}

		GenericXmlApplicationContext context = new GenericXmlApplicationContext();
		context.load(resourcesToLoad);

		if (profiles!=null) {
			context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
		}

		// Simulate what happens in the webapp when the YamlServletProfileInitializer kicks in
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new FileSystemResource("./src/test/resources/test/config/login.yml")});
		context.getEnvironment().getPropertySources().addLast(new PropertiesPropertySource("servletProperties", factory.getObject()));

		context.refresh();

		return context;
		
	}

}
