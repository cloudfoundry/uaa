package org.cloudfoundry.identity.uaa.impl.config;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

/**
 * Factory for Properties that reads from the Spring context {@link Environment} where it can.
 *
 * @author Dave Syer
 */
public class EnvironmentPropertiesFactoryBean implements FactoryBean<Properties>, EnvironmentAware {

  private Environment environment;

  private Map<String, Object> defaultProperties = new HashMap<String, Object>();

  public void setDefaultProperties(Properties defaultProperties) {
    this.defaultProperties.clear();
    for (Object key : defaultProperties.keySet()) {
      this.defaultProperties.put((String) key, defaultProperties.get(key));
    }
  }

  @Override
  public void setEnvironment(Environment environment) {
    this.environment = environment;
  }

  @Override
  public Properties getObject() {

    Properties result = new Properties();
    EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
    factory.setEnvironment(environment);
    factory.setDefaultProperties(defaultProperties);
    Map<String, ?> map = factory.getObject();
    for (Object key : map.keySet()) {
      Object value = map.get(key);
      if (value == null) {
        value = "";
      }
      result.put(key, value);
    }

    return result;
  }

  @Override
  public Class<?> getObjectType() {
    return Properties.class;
  }

  @Override
  public boolean isSingleton() {
    return true;
  }
}
