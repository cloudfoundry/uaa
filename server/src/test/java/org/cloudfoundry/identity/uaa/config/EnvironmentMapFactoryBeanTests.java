package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.impl.config.EnvironmentMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.util.StringUtils;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EnvironmentMapFactoryBeanTests {

    @Test
    void testDefaultProperties() {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("foo=foo"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("foo", properties.get("foo"));
    }

    @Test
    void testRawPlaceholderProperties() {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("foo=${bar}"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("${bar}", properties.get("foo"));
    }

    @Test
    void testPlaceholderProperties() {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addLast(new NestedMapPropertySource("override", getProperties("bar=${spam}")));
        factory.setEnvironment(environment);
        factory.setDefaultProperties(getProperties("foo=baz"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("baz", properties.get("foo"));
        assertEquals("${spam}", properties.get("bar"));
    }

    @Test
    void testOverrideProperties() {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("foo=foo"));
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addLast(new NestedMapPropertySource("override", getProperties("foo=bar")));
        factory.setEnvironment(environment);
        Map<String, ?> properties = factory.getObject();
        assertEquals("bar", properties.get("foo"));
    }

    private static Map<String, ?> getProperties(String input) {
        HashMap<String, Object> result = new HashMap<>();
        Properties properties = StringUtils.splitArrayElementsIntoProperties(
                StringUtils.commaDelimitedListToStringArray(input), "=");
        for (Enumeration<?> keys = properties.propertyNames(); keys.hasMoreElements(); ) {
            String key = (String) keys.nextElement();
            result.put(key, properties.getProperty(key));
        }
        return result;
    }

}
