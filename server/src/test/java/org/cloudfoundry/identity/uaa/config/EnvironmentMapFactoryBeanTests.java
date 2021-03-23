package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.impl.config.EnvironmentMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.StandardEnvironment;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EnvironmentMapFactoryBeanTests {

    private EnvironmentMapFactoryBean factory;

    @BeforeEach
    void setUp() {
        factory = new EnvironmentMapFactoryBean();
    }

    @Test
    void defaultProperties() {
        Map<String, String> inputProperties = new HashMap<>();
        inputProperties.put("foo", "foo");

        factory.setDefaultProperties(inputProperties);
        Map<String, ?> properties = factory.getObject();
        assertEquals("foo", properties.get("foo"));
    }

    @Test
    void rawPlaceholderProperties() {
        Map<String, String> inputProperties = new HashMap<>();
        inputProperties.put("foo", "${bar}");

        factory.setDefaultProperties(inputProperties);
        Map<String, ?> properties = factory.getObject();
        assertEquals("${bar}", properties.get("foo"));
    }

    @Test
    void placeholderProperties() {
        Map<String, String> inputProperties = new HashMap<>();
        inputProperties.put("foo", "baz");

        Map<String, String> overrideProperties = new HashMap<>();
        overrideProperties.put("bar", "${spam}");

        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addLast(new NestedMapPropertySource("override", overrideProperties));
        factory.setEnvironment(environment);
        factory.setDefaultProperties(inputProperties);
        Map<String, ?> properties = factory.getObject();
        assertEquals("baz", properties.get("foo"));
        assertEquals("${spam}", properties.get("bar"));
    }

    @Test
    void overrideProperties() {
        Map<String, String> inputProperties = new HashMap<>();
        inputProperties.put("foo", "foo");

        Map<String, String> overrideProperties = new HashMap<>();
        overrideProperties.put("foo", "bar");

        factory.setDefaultProperties(inputProperties);
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addLast(new NestedMapPropertySource("override", overrideProperties));
        factory.setEnvironment(environment);
        Map<String, ?> properties = factory.getObject();
        assertEquals("bar", properties.get("foo"));
    }

}
