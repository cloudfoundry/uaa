package org.cloudfoundry.identity.uaa.impl.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Factory for Maps that reads from the Spring context {@link Environment} where
 * it can.
 *
 * @author Dave Syer
 */
public class EnvironmentMapFactoryBean implements FactoryBean<Map<String, ?>>, EnvironmentAware {

    private static final Logger logger = LoggerFactory.getLogger(EnvironmentMapFactoryBean.class);

    private static final List<String> STATIC_PROPERTY_SOURCES = List.of(
            StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME,
            StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);

    private Environment environment;

    private Map<String, ?> defaultProperties = new HashMap<>();

    public void setDefaultProperties(Map<String, ?> defaultProperties) {
        this.defaultProperties = defaultProperties;
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public Map<String, Object> getObject() {
        Map<String, Object> result = new LinkedHashMap<>();
        // The result is the default application properties overridden with
        // Spring environment values - reversing the
        // order of the placeholder configurers in the application context.
        for (Map.Entry<String, ?> entry : defaultProperties.entrySet()) {
            String name = entry.getKey();
            if (environment != null && environment.containsProperty(name)) {
                Object value = environment.getProperty(name, Object.class);
                logger.debug("From Environment: {}", name);
                result.put(name, value);
            } else {
                logger.debug("From Defaults: {}", name);
                result.put(name, entry.getValue());
            }
        }
        // Any properties added only in the environment can be picked up here...
        if (environment instanceof ConfigurableEnvironment configurableEnvironment) {
            for (PropertySource<?> source : configurableEnvironment.getPropertySources()) {
                if (source instanceof EnumerablePropertySource<?> enumerable && !STATIC_PROPERTY_SOURCES.contains(source.getName())) {
                    for (String name : enumerable.getPropertyNames()) {
                        Object value = source.getProperty(name);
                        if (value instanceof String string) {
                            // Unresolved placeholders are legal.
                            value = environment.resolvePlaceholders(string);
                        }
                        result.put(name, value);
                    }
                }
            }
        }
        return result;
    }

    @Override
    public Class<?> getObjectType() {
        return Map.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }
}
