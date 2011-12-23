package org.cloudfoundry.identity.uaa.varz;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;
import java.util.Set;

import javax.management.MBeanServerConnection;
import javax.management.ObjectName;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jmx.support.MBeanServerFactoryBean;

public class MBeanMapTests {

	private ObjectMapper mapper = new ObjectMapper();
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
		Map<String,String>  properties = (Map<String, String>) result.get("system_properties");
		// System.err.println(properties);
		assertTrue(properties.containsKey("java.vm.version"));
		String json = mapper.writeValueAsString(result);
		// System.err.println(json);
		assertNotNull(json);
	}

}
