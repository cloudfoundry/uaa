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
package org.cloudfoundry.identity.uaa.varz;

import static org.junit.Assert.assertNotNull;

import javax.management.MBeanServerConnection;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.jmx.support.MBeanServerFactoryBean;

public class VarzEndpointTests {

	private MBeanServerConnection server;
	private VarzEndpoint endpoint;

	@Before
	public void start() throws Exception {
		MBeanServerFactoryBean factory = new MBeanServerFactoryBean();
		factory.setLocateExistingServerIfPossible(true);
		factory.afterPropertiesSet();
		server = factory.getObject();
		endpoint = new VarzEndpoint();
		endpoint.setServer(server);
	}

	@Test
	public void testListDomains() throws Exception {
		assertNotNull(endpoint.getMBeanDomains());
	}

	@Test
	public void testListMBeans() throws Exception {
		assertNotNull(endpoint.getMBeans("java.lang:type=Runtime,*"));
	}

	@Test
	public void testDefaultVarz() throws Exception {
		assertNotNull(endpoint.getVarz());
	}

	@Test
	public void testActiveProfiles() throws Exception {
		endpoint.setEnvironment(new StandardEnvironment());
		assertNotNull(endpoint.getVarz().get("spring.profiles.active"));
	}

}
