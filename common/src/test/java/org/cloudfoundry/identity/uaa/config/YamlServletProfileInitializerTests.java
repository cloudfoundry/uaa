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
import org.springframework.core.io.ByteArrayResource;
import org.springframework.util.Log4jConfigurer;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.StandardServletEnvironment;

/**
 * @author Dave Syer
 * 
 */
public class YamlServletProfileInitializerTests {

	private YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();

	private ConfigurableWebApplicationContext context = Mockito.mock(ConfigurableWebApplicationContext.class);

	private StandardServletEnvironment environment = new StandardServletEnvironment();

	private ServletConfig servletConfig = Mockito.mock(ServletConfig.class);

	private ServletContext servletContext = Mockito.mock(ServletContext.class);

	private String activeProfiles;

	@Before
	public void setup() {
		Mockito.when(context.getServletConfig()).thenReturn(servletConfig);
		Mockito.when(context.getServletContext()).thenReturn(servletContext);
		Mockito.when(context.getEnvironment()).thenReturn(environment);
		Mockito.doAnswer(new Answer<Void>() {
			@Override
			public Void answer(InvocationOnMock invocation) throws Throwable {
				System.err.println(invocation.getArguments()[0]);
				return null;
			}
		}).when(servletContext).log(Mockito.anyString());
		Mockito.when(servletContext.getContextPath()).thenReturn("/context");
		activeProfiles = System.getProperty("spring.profiles.active");
	}

	@After
	public void cleanup() throws Exception {
		System.clearProperty("APPLICATION_CONFIG_URL");
		System.clearProperty("LOG_FILE");
		System.clearProperty("LOG_PATH");
		Log4jConfigurer.initLogging("classpath:log4j.properties");
		if (activeProfiles != null) {
			System.setProperty("spring.profiles.active", activeProfiles);
		}
		else {
			System.clearProperty("spring.profiles.active");
		}
	}

	@Test
	public void testLoadDefaultResource() throws Exception {

		Mockito.when(context.getResource(Matchers.contains("${APPLICATION_CONFIG_URL}"))).thenReturn(
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
				new ByteArrayResource("logging:\n  file: /tmp/bar.log".getBytes()));
		initializer.initialize(context);
		assertEquals("/tmp/bar.log", System.getProperty("LOG_FILE"));
	}

	@Test
	public void testLog4jPathFromYaml() throws Exception {
		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(
				new ByteArrayResource("logging:\n  path: /tmp/log/bar".getBytes()));
		initializer.initialize(context);
		assertEquals("/tmp/log/bar", System.getProperty("LOG_PATH"));
	}

	@Test
	public void testLog4jConfigurationFromYaml() throws Exception {
		Mockito.when(context.getResource(Matchers.anyString())).thenReturn(
				new ByteArrayResource("logging:\n  config: bar".getBytes()));
		initializer.initialize(context);
	}

	@Test
	public void testLoadServletConfiguredFilename() throws Exception {

		Mockito.when(servletConfig.getInitParameter("APPLICATION_CONFIG_FILE")).thenReturn("/config/path/foo.yml");
		Mockito.when(context.getResource(Matchers.eq("file:/config/path/foo.yml"))).thenReturn(
				new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

	@Test
	public void testLoadServletConfiguredResource() throws Exception {

		Mockito.when(servletConfig.getInitParameter("environmentConfigLocations")).thenReturn("foo.yml");
		Mockito.when(context.getResource(Matchers.eq("foo.yml"))).thenReturn(
				new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

	@Test
	public void testLoadContextConfiguredResource() throws Exception {

		Mockito.when(servletContext.getInitParameter("environmentConfigLocations")).thenReturn("foo.yml");
		Mockito.when(context.getResource(Matchers.eq("foo.yml"))).thenReturn(
				new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

	@Test
	public void testLoadReplacedResource() throws Exception {

		System.setProperty("APPLICATION_CONFIG_URL", "file:foo/uaa.yml");

		Mockito.when(context.getResource(Matchers.eq("file:foo/uaa.yml"))).thenReturn(
				new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

	@Test
	public void testLoadReplacedResourceFromFileLocation() throws Exception {

		System.setProperty("APPLICATION_CONFIG_FILE", "foo/uaa.yml");

		Mockito.when(context.getResource(Matchers.eq("file:foo/uaa.yml"))).thenReturn(
				new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()));

		initializer.initialize(context);

		assertEquals("bar", environment.getProperty("foo"));
		assertEquals("baz", environment.getProperty("spam.foo"));

	}

}
