package org.cloudfoundry.identity.uaa.yml;

import org.cloudfoundry.identity.uaa.integration.feature.ImplicitGrantIT;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTimeout;

class YamlProcessorTest {
    /**
     * Integration tests using spring, such as {@link ImplicitGrantIT}, have been taking around 20 seconds to start up.
     * This is due to the {@link Yaml} parser having a hard time parsing uaa.yml, which contains very long comments.
     * This test ensures that the parser will parse swiftly.
     */
    @Test
    void loadAll_yamlIsFullOfLongComments_yamlLoadsInUnderASecond() {
        assertTimeout(Duration.ofSeconds(1), () -> {
            DefaultResourceLoader loader = new DefaultResourceLoader();
            Resource resource = loader.getResource("uaa.yml");
            InputStream inputStream = resource.getInputStream();
            Yaml yaml = new Yaml();

            Iterable<Object> objects = yaml.loadAll(inputStream);
            for (Object o : objects) {
                System.out.println(o);
            }
        });
    }
}
