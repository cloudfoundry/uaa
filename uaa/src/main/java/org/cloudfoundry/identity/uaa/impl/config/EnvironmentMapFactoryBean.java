package org.cloudfoundry.identity.uaa.impl.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.*;

import java.util.*;

/**
 * Factory for Maps that reads from the Spring context {@link Environment} where
 * it can.
 *
 * @author Dave Syer
 */
public class EnvironmentMapFactoryBean implements FactoryBean<Map<String, ?>>, EnvironmentAware {

    private static Logger logger = LoggerFactory.getLogger(EnvironmentMapFactoryBean.class);

    private static final Collection<String> STATIC_PROPERTY_SOURCES = Arrays.asList(
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
    public Map<String, ?> getObject() {
        Map<String, Object> result = new LinkedHashMap<>();
        // The result is the default application properties overridden with
        // Spring environment values - reversing the
        // order of the placeholder configurers in the application context.
        for (Object key : defaultProperties.keySet()) {
            String name = (String) key;
            if (environment != null && environment.containsProperty(name)) {
                Object value = environment.getProperty(name, Object.class);
                logger.debug("From Environment: " + name);
                result.put(name, value);
            } else {
                logger.debug("From Defaults: " + name);
                result.put(name, defaultProperties.get(key));
            }
        }
        // Any properties added only in the environment can be picked up here...
        if (environment instanceof ConfigurableEnvironment) {
            for (PropertySource<?> source : ((ConfigurableEnvironment) environment).getPropertySources()) {
                if (source instanceof EnumerablePropertySource && !STATIC_PROPERTY_SOURCES.contains(source.getName())) {
                    @SuppressWarnings("rawtypes")
                    EnumerablePropertySource enumerable = (EnumerablePropertySource) source;
                    for (String name : enumerable.getPropertyNames()) {
                        Object value = source.getProperty(name);
                        if (value instanceof String) {
                            // Unresolved placeholders are legal.
                            value = environment.resolvePlaceholders((String) value);
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
