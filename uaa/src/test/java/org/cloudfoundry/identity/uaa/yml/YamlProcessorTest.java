package org.cloudfoundry.identity.uaa.yml;

import org.cloudfoundry.identity.uaa.integration.feature.ImplicitGrantIT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Stopwatch;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Created by taitz.
 */
public class YamlProcessorTest {

    @Rule
    public Stopwatch stopwatch = new Stopwatch() {
    };


    /**
     * Integration tests using spring, such as {@link ImplicitGrantIT}, have been taking around 20 seconds to start up.
     * This is due to the {@link Yaml} parser having a hard time parsing uaa.yml, which contains very long comments.
     * This test ensures that the parser will parse swiftly.
     */
    @Test
    public void loadAll_yamlIsFullOfLongComments_yamlLoadsInUnderASecond() throws IOException {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource resource = loader.getResource("uaa.yml");
        InputStream inputStream = resource.getInputStream();
        Yaml yaml = new Yaml();

        Iterable<Object> objects = yaml.loadAll(inputStream);
        for (Object o : objects) {
            System.out.println(o);
        }

        assertEquals(1, stopwatch.runtime(SECONDS), 1);
    }
}