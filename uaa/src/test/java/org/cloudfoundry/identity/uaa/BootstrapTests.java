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

import java.util.Properties;

import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;
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
	public void cleanup() {
		System.clearProperty("spring.profiles.active");		
		System.clearProperty("CLOUD_FOUNDRY_CONFIG_PATH");
		if (context!=null) {
			context.close();
		}
	}

	@Test
	public void testRootContextWithJdbcUsers() throws Exception {
		System.setProperty("spring.profiles.active", "jdbc,hsqldb,!private,!legacy");
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		assertNotNull(context.getBean("userDatabase", JdbcUaaUserDatabase.class));
	}

	@Test
	public void testRootContextWithDevUsers() throws Exception {
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		assertNotNull(context.getBean("userDatabase", InMemoryUaaUserDatabase.class));
	}

	@Test
	public void testRootContextWithJdbcSecureUsers() throws Exception {
		System.setProperty("spring.profiles.active", "jdbc,hsqldb,!private,!legacy");
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		assertNotNull(context.getBean("userDatabase", JdbcUaaUserDatabase.class));
		FilterChainProxy filterChain = context.getBean(FilterChainProxy.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filterChain.doFilter(new MockHttpServletRequest("GET", "/Users"), response, new MockFilterChain());
		assertEquals("http://localhost/login", response.getRedirectedUrl());
	}

	@Test
	public void testRootContextWithJdbcUnsecureUsers() throws Exception {
		System.setProperty("spring.profiles.active", "jdbc,hsqldb,private,!legacy");
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		assertNotNull(context.getBean("userDatabase", JdbcUaaUserDatabase.class));
		FilterChainProxy filterChain = context.getBean(FilterChainProxy.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filterChain.doFilter(new MockHttpServletRequest("GET", "/Users"), response, new MockFilterChain());
		assertEquals(null, response.getRedirectedUrl());
	}

	@Test
	public void testOverrideYmlConfig() throws Exception {
		System.setProperty("CLOUD_FOUNDRY_CONFIG_PATH", "src/test/resources/test/config");
		System.setProperty("spring.profiles.active", "jdbc,hsqldb,!private,legacy");
		context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		Properties properties = context.getBean("applicationProperties", Properties.class);
		assertEquals("bar", properties.get("foo"));
	}

}
