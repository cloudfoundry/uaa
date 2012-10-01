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
package org.cloudfoundry.identity.uaa.varz;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import java.util.Properties;

import javax.management.MBeanServerConnection;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.jmx.support.MBeanServerFactoryBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.util.StringUtils;

public class VarzEndpointTests {

	private MBeanServerConnection server;

	private VarzEndpoint endpoint;

	private MockHttpServletRequest request;

	@Before
	public void start() throws Exception {
		MBeanServerFactoryBean factory = new MBeanServerFactoryBean();
		factory.setLocateExistingServerIfPossible(true);
		factory.afterPropertiesSet();
		server = factory.getObject();
		endpoint = new VarzEndpoint();
		endpoint.setServer(server);
		request = new MockHttpServletRequest();
		request.setServerPort(80);
		request.setServerName("uaa.vcap.me");
		request.setScheme("http");
	}

	@Test
	public void testGetConfiguredBaseUrl() throws Exception {
		endpoint.setBaseUrl("http://uaa.cloudfoundry.com");
		assertEquals("http://uaa.cloudfoundry.com", endpoint.getBaseUrl(request));
	}

	@Test
	public void testGetCopmutedBaseUrl() throws Exception {
		assertEquals("http://uaa.vcap.me", endpoint.getBaseUrl(request));
	}

	@Test
	public void testListDomains() throws Exception {
		assertNotNull(endpoint.getMBeanDomains());
	}

	@Test
	public void testListMBeans() throws Exception {
		assertNotNull(endpoint.getDomain("java.lang", "type=Runtime,*"));
	}

	@Test
	public void testDefaultVarz() throws Exception {
		Map<String, ?> varz = endpoint.getVarz("http://uua.vcap.me");
		// System.err.println(varz);
		assertNotNull(varz.get("mem"));
		assertTrue((Long)varz.get("mem")<1024*1024); // kB, so less than 1GB
	}

	@Test
	public void testVarzWithConfig() throws Exception {
		Properties properties = StringUtils.splitArrayElementsIntoProperties(
				StringUtils.commaDelimitedListToStringArray("foo=bar,password=spam,client.secret=baz"), "=");
		endpoint.setEnvironmentProperties(properties);
		Map<String, ?> varz = endpoint.getVarz("http://uua.vcap.me");
		// System.err.println(varz);
		@SuppressWarnings("unchecked")
		Map<String, ?> map = (Map<String, ?>) varz.get("config");
		assertNotNull(map);
		assertTrue(map.containsKey("foo"));
		assertEquals("#", map.get("password"));
		assertEquals("#", map.get("client.secret"));
	}

	@Test
	public void testActiveProfiles() throws Exception {
		endpoint.setEnvironment(new StandardEnvironment());
		assertNotNull(endpoint.getVarz("http://uua.vcap.me").get("spring.profiles.active"));
	}

}
