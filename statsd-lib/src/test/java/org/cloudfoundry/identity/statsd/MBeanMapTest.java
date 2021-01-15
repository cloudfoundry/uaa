package org.cloudfoundry.identity.statsd;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jmx.support.MBeanServerFactoryBean;

import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MBeanMapTest {

    private MBeanServerConnection server;

    @BeforeEach
    void start() {
        MBeanServerFactoryBean factory = new MBeanServerFactoryBean();
        factory.setLocateExistingServerIfPossible(true);
        factory.afterPropertiesSet();
        server = factory.getObject();
    }

    @Test
    void listDomain() throws Exception {
        Set<ObjectName> names = server.queryNames(ObjectName.getInstance("java.lang:type=Runtime,*"), null);
        System.err.println(names);
        assertEquals(1, names.size());
        MBeanMap result = new MBeanMap(server, names.iterator().next());
        @SuppressWarnings("unchecked")
        Map<String, String> properties = (Map<String, String>) result.get("system_properties");
        assertTrue(properties.containsKey("java.vm.version"));
    }

}