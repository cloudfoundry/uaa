package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.springframework.beans.factory.config.YamlMapFactoryBean;
import org.springframework.beans.factory.config.YamlProcessor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;
import org.yaml.snakeyaml.Yaml;

import java.util.Map;

public class NestedMapPropertySourceFactory implements PropertySourceFactory {
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
