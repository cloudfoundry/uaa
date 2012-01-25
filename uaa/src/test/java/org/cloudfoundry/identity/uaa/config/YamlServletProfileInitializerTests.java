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
import javax.servlet.ServletContext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.util.Log4jConfigurer;
import org.springframework.web.context.ConfigurableWebApplicationContext;

/**
 * @author Dave Syer
 * 
 */
public class YamlServletProfileInitializerTests {

	private YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();

	private ConfigurableWebApplicationContext context = Mockito.mock(ConfigurableWebApplicationContext.class);

	private StandardEnvironment environment = new StandardEnvironment();

	private ServletConfig servletConfig = Mockito.mock(ServletConfig.class);

	private String activeProfiles;

	@Before
	public void setup() {
		Mockito.when(context.getServletConfig()).thenReturn(servletConfig);
		ServletContext servletContext = Mockito.mock(ServletContext.class);
		Mockito.when(context.getServletContext()).thenReturn(servletContext);
		Mockito.when(context.getEnvironment()).thenReturn(environment);
		Mockito.doAnswer(new Answer<Void>() {
			@Override
			public Void answer(InvocationOnMock invocation) throws Throwable {
				System.err.println(invocation.getArguments()[0]);
				return null;
			}
		}).when(servletContext).log(Mockito.anyString());
		activeProfiles = System.getProperty("spring.profiles.active");
	}

	@After
	public void cleanup() throws Exception {
		System.clearProperty("CLOUD_FOUNDRY_CONFIG_PATH");
		System.clearProperty("LOG_FILE");
		System.clearProperty("LOG_PATH");
		Log4jConfigurer.initLogging("classpath:log4j.properties");
		if (activeProfiles!=null) {
			System.setProperty("spring.profiles.active", activeProfiles);
		}
	}

	@Test
	public void testLoadDefaultResource() throws Exception {

		Mockito.when(context.getResource(Matchers.eq("file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml"))).thenReturn(
				new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

	@Test
	public void testActiveProfiles() throws Exception {
		
		System.setProperty("spring.profiles.active", "foo");

		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(
				new ByteArrayResource("spring_profiles: bar".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getActiveProfiles()[0]);

	}

	@Test
	public void testActiveProfilesFromYaml() throws Exception {

		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(
				new ByteArrayResource("spring_profiles: bar".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getActiveProfiles()[0]);

	}

	@Test
	public void testLog4jFileFromYaml() throws Exception {
		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(
				new ByteArrayResource("logging:\n  file: /tmp/bar".getBytes()));
		initializer.initialize(context);
		assertEquals("/tmp/bar", System.getProperty("LOG_FILE"));
	}

	@Test
	public void testLog4jPathFromYaml() throws Exception {
		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(
				new ByteArrayResource("logging:\n  path: /tmp/bar".getBytes()));
		initializer.initialize(context);
		assertEquals("/tmp/bar", System.getProperty("LOG_PATH"));
	}

	@Test
	public void testLog4jConfigurationFromYaml() throws Exception {
		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(
				new ByteArrayResource("logging:\n  config: bar".getBytes()));
		initializer.initialize(context);
	}

	@Test
	public void testLoadConfiguredResource() throws Exception {

		Mockito.when(servletConfig.getInitParameter("environmentConfigFile")).thenReturn("foo.yml");
		Mockito.when(context.getResource(Matchers.eq("foo.yml"))).thenReturn(
				new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

	@Test
	public void testLoadReplacedResource() throws Exception {

		System.setProperty("CLOUD_FOUNDRY_CONFIG_PATH", "foo");

		Mockito.when(context.getResource(Matchers.eq("file:foo/uaa.yml"))).thenReturn(
				new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

}
