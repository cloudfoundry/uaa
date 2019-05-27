package org.cloudfoundry.identity.uaa.test;

import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;
import org.yaml.snakeyaml.Yaml;

import java.util.Map;

/**
 * @Deprecated. Use {@link org.cloudfoundry.identity.uaa.DefaultTestContext} instead.
 * This is part of the uaa module, so move it to the server module if you need it
 */
@Deprecated
@Configuration
@PropertySource(value = {
  "file:../uaa/src/test/resources/test/bootstrap/all-properties-set.yml"
}, factory = NestedMapPropertySourceFactory.class)
@ImportResource(locations = {
  "file:../uaa/src/main/webapp/WEB-INF/spring-servlet.xml"
})
public class TestWebAppContext implements InitializingBean {
    @Autowired
    DataSource dataSource;

    @Bean
    public static PropertySourcesPlaceholderConfigurer properties() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Override
    public void afterPropertiesSet() {
    }
}

class NestedMapPropertySourceFactory implements PropertySourceFactory {
    @Override
    public org.springframework.core.env.PropertySource<?> createPropertySource(String name, EncodedResource resource) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        factory.setResources(new Resource[]{resource.getResource()});

        Map<String, Object> yamlMap = factory.getObject();
        String yamlStr = (new Yaml()).dump(yamlMap);
        yamlMap.put("environmentYamlKey", yamlStr);

        return new NestedMapPropertySource("servletConfigYaml", yamlMap);
    }
}