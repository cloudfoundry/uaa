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
