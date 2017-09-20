/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.statsd;

import org.junit.Before;
import org.junit.Test;
import org.springframework.jmx.support.MBeanServerFactoryBean;

import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertTrue;

public class MBeanMapTests {

	private MBeanServerConnection server;

	@Before
	public void start() throws Exception {
		MBeanServerFactoryBean factory = new MBeanServerFactoryBean();
		factory.setLocateExistingServerIfPossible(true);
		factory.afterPropertiesSet();
		server = factory.getObject();
	}

	@Test
	public void testListDomain() throws Exception {
		Set<ObjectName> names = server.queryNames(ObjectName.getInstance("java.lang:type=Runtime,*"), null);
		System.err.println(names);
		assertTrue(names.size() == 1);
		MBeanMap result = new MBeanMap(server, names.iterator().next());
		@SuppressWarnings("unchecked")
		Map<String,String>  properties = (Map<String, String>) result.get("system.properties");
		assertTrue(properties.containsKey("java.vm.version"));
	}

}
