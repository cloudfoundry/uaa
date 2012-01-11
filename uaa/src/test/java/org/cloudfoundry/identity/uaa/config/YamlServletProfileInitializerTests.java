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

import static org.junit.Assert.assertEquals;

import javax.servlet.ServletConfig;

import org.junit.After;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.web.context.ConfigurableWebApplicationContext;

/**
 * @author Dave Syer
 *
 */
public class YamlServletProfileInitializerTests {
	
	private YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();
	
	private ConfigurableWebApplicationContext context = Mockito.mock(ConfigurableWebApplicationContext.class);

	private StandardEnvironment environment = new StandardEnvironment();
	
	@After
	public void cleanup() {
		System.clearProperty("CLOUD_FOUNDRY_CONFIG_PATH");
	}
	
	@Test
	public void testLoadDefaultResource() throws Exception {
		
		ServletConfig servletConfig = Mockito.mock(ServletConfig.class);
		Mockito.when(context.getServletConfig()).thenReturn(servletConfig);
		Mockito.when(context.getResource(Matchers.eq("${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml"))).thenReturn(new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));
		Mockito.when(context.getEnvironment()).thenReturn(environment);
		
		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

	@Test
	public void testActiveProfiles() throws Exception {
		
		ServletConfig servletConfig = Mockito.mock(ServletConfig.class);
		Mockito.when(context.getServletConfig()).thenReturn(servletConfig);
		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(new ByteArrayResource("spring.profiles.active: bar".getBytes()));
		Mockito.when(context.getEnvironment()).thenReturn(environment);
		
		initializer.initialize(context);

		assertEquals("bar", environment.getActiveProfiles()[0]);

	}

	@Test
	public void testActiveProfilesFromYaml() throws Exception {
		
		ServletConfig servletConfig = Mockito.mock(ServletConfig.class);
		Mockito.when(context.getServletConfig()).thenReturn(servletConfig);
		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(new ByteArrayResource("spring_profiles: bar".getBytes()));
		Mockito.when(context.getEnvironment()).thenReturn(environment);
		
		initializer.initialize(context);

		assertEquals("bar", environment.getActiveProfiles()[0]);

	}

	@Test
	public void testLoadConfiguredResource() throws Exception {
		
		ServletConfig servletConfig = Mockito.mock(ServletConfig.class);
		Mockito.when(context.getServletConfig()).thenReturn(servletConfig);
		Mockito.when(servletConfig.getInitParameter("environmentConfigFile")).thenReturn("foo.yml");
		Mockito.when(context.getResource(Matchers.eq("foo.yml"))).thenReturn(new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));
		Mockito.when(context.getEnvironment()).thenReturn(environment);
		
		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

	@Test
	public void testLoadReplacedResource() throws Exception {

		System.setProperty("CLOUD_FOUNDRY_CONFIG_PATH", "foo");

		ServletConfig servletConfig = Mockito.mock(ServletConfig.class);
		Mockito.when(context.getServletConfig()).thenReturn(servletConfig);
		Mockito.when(context.getResource(Matchers.eq("foo/uaa.yml"))).thenReturn(new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));
		Mockito.when(context.getEnvironment()).thenReturn(environment);
		
		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

}
