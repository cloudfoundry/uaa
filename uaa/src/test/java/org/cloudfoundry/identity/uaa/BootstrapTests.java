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
package org.cloudfoundry.identity.uaa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.config.YamlPropertiesFactoryBean;
import org.cloudfoundry.identity.uaa.oauth.UaaUserApprovalHandler;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.varz.VarzEndpoint;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StringUtils;

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
		System.clearProperty("CLOUD_FOUNDRY_CONFIG_PATH");
		System.clearProperty("UAA_CONFIG_FILE");
		if (context != null) {
			if (context.containsBean("scimEndpoints")) {
				TestUtils.deleteFrom(context.getBean("dataSource", DataSource.class), "sec_audit");
			}
			context.close();
		}
	}

	@Test
	public void testVarzContextDefaults() throws Exception {
		context = getServletContext("file:./src/main/webapp/WEB-INF/varz-servlet.xml");
		assertNotNull(context.getBean("varzEndpoint", VarzEndpoint.class));
	}

	@Test
	public void testRootContextDefaults() throws Exception {
		context = getServletContext("hsqldb", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
		assertNotNull(context.getBean("userDatabase", JdbcUaaUserDatabase.class));
		FilterChainProxy filterChain = context.getBean(FilterChainProxy.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/Users");
		request.setServletPath("");
		request.setPathInfo("/Users");
		filterChain.doFilter(request, response, new MockFilterChain());
		assertEquals(401, response.getStatus());
	}

	@Test
	public void testOverrideYmlConfigPath() throws Exception {
		System.setProperty("UAA_CONFIG_PATH", "./src/test/resources/test/config");
		context = getServletContext("hsqldb", "file:./src/main/webapp/WEB-INF/spring-servlet.xml",
				"classpath:/test/config/test-override.xml");
		assertEquals("different", context.getBean("foo", String.class));
		assertEquals("[vmc, my, support]",
				ReflectionTestUtils.getField(context.getBean(UaaUserApprovalHandler.class), "autoApproveClients")
						.toString());
		ScimUserProvisioning users = context.getBean(ScimUserProvisioning.class);
		assertTrue(users.retrieveUsers().size() > 0);
	}

	private GenericXmlApplicationContext getServletContext(String... resources) {
		String profiles = null;
		String[] resourcesToLoad = resources;
		if (!resources[0].endsWith(".xml")) {
			profiles = resources[0];
			resourcesToLoad = new String[resources.length - 1];
			System.arraycopy(resources, 1, resourcesToLoad, 0, resourcesToLoad.length);
		}

		GenericXmlApplicationContext context = new GenericXmlApplicationContext();
		if (profiles != null) {
			context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
		}
		
		context.load(resourcesToLoad);

		// Simulate what happens in the webapp when the YamlServletProfileInitializer kicks in
		String yaml = System.getProperty("UAA_CONFIG_PATH");
		if (yaml != null) {
			YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
			factory.setResources(new Resource[] { new FileSystemResource(yaml + "/uaa.yml") });
			context.getEnvironment().getPropertySources()
					.addLast(new PropertiesPropertySource("servletProperties", factory.getObject()));
		}

		context.refresh();

		return context;
	}

}
