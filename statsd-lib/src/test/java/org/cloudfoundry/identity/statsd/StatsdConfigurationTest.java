package org.cloudfoundry.identity.statsd;

import com.timgroup.statsd.StatsDClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = StatsdConfiguration.class)
class StatsdConfigurationTest {
    @Autowired
    private StatsDClient statsDClient;
    @Autowired
    private UaaMetricsEmitter metricsEmitter;

    @Test
    void wiresUaaMetricsEmitter() {
        assertThat(metricsEmitter)
                .isInstanceOf(UaaMetricsEmitter.class);

        assertThat(statsDClient)
                .isInstanceOf(StatsDClient.class);

        StatsDClient emitterClient = (StatsDClient) ReflectionTestUtils.getField(metricsEmitter, "statsDClient");
        assertThat(emitterClient)
                .isSameAs(statsDClient);
    }
}
