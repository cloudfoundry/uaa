/*
 * Copyright 2006-2010 the original author or authors.
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

package org.cloudfoundry.identity.uaa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.cloudfoundry.identity.uaa.config.YamlPropertiesFactoryBean;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.jdbc.core.JdbcOperations;
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
	public void cleanup() {
		System.clearProperty("spring.profiles.active");		
		System.clearProperty("CLOUD_FOUNDRY_CONFIG_PATH");
		System.clearProperty("UAA_CONFIG_FILE");
		if (context!=null) {
			JdbcOperations jdbcTemplate = context.getBean(JdbcOperations.class);
			jdbcTemplate.execute("SHUTDOWN");
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

		context = new GenericXmlApplicationContext();
		context.load(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"), new ClassPathResource("/test/config/test-override.xml"));

		context.getEnvironment().setActiveProfiles("hsqldb", "legacy");

		// Simulate what happens in the webapp when the YamlServletProfileInitializer kicks in
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResource(new FileSystemResource("src/test/resources/test/config/uaa.yml"));
		context.getEnvironment().getPropertySources().addLast(new PropertiesPropertySource("servletProperties", factory.getObject()));

		context.refresh();

		assertEquals("different", context.getBean("foo", String.class));

	}

}
