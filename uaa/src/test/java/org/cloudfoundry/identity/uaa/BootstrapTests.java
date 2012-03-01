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
package org.cloudfoundry.identity.uaa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.config.YamlPropertiesFactoryBean;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.junit.After;
import org.junit.Test;
import org.springframework.batch.admin.service.JobService;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterChainProxy;

/**
 * @author Dave Syer
 *
 */
public class BootstrapTests {
	
	private GenericXmlApplicationContext context;
	
	@After
	public void cleanup() throws Exception {
		System.clearProperty("spring.profiles.active");		
		System.clearProperty("CLOUD_FOUNDRY_CONFIG_PATH");
		System.clearProperty("UAA_CONFIG_FILE");
		if (context!=null) {
			TestUtils.dropSchema(context.getBean(DataSource.class));
			context.close();
		}
	}

	@Test
	public void testRootContextWithJdbcUsers() throws Exception {
		System.setProperty("spring.profiles.active", "hsqldb,!legacy");
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		assertNotNull(context.getBean("userDatabase", JdbcUaaUserDatabase.class));
	}

	@Test
	public void testRootContextDefaults() throws Exception {
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		assertNotNull(context.getBean("userDatabase", JdbcUaaUserDatabase.class));
	}

	@Test
	public void testBatchContextDefaults() throws Exception {
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/batch-servlet.xml"));
		assertNotNull(context.getBean("jobService", JobService.class));
	}

	@Test
	public void testRootContextWithJdbcSecureUsers() throws Exception {
		System.setProperty("spring.profiles.active", "hsqldb,!legacy");
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
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
	public void testLegacyProfileAndOverrideYmlConfigPath() throws Exception {

		context = getServletContext("file:./src/main/webapp/WEB-INF/spring-servlet.xml", "classpath:/test/config/test-override.xml");
		assertEquals("different", context.getBean("foo", String.class));

	}

	private GenericXmlApplicationContext getServletContext(String... resources) {

		GenericXmlApplicationContext context = new GenericXmlApplicationContext();
		context.load(resources);

		context.getEnvironment().setActiveProfiles("hsqldb", "legacy");

		// Simulate what happens in the webapp when the YamlServletProfileInitializer kicks in
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResource(new FileSystemResource("src/test/resources/test/config/uaa.yml"));
		context.getEnvironment().getPropertySources().addLast(new PropertiesPropertySource("servletProperties", factory.getObject()));

		context.refresh();

		return context;
		
	}

}
