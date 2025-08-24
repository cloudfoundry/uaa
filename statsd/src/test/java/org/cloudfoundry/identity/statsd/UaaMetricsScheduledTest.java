package org.cloudfoundry.identity.statsd;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@WebAppConfiguration
class UaaMetricsScheduledTest {

    @Autowired
    private UaaMetricsEmitter uaaMetricsEmitter;

    @Test
    void emittingMetrics_Is_Scheduled() throws Exception {
        Scheduled schedulerAnnotation = uaaMetricsEmitter.getClass().getMethod("emitMetrics").getAnnotation(Scheduled.class);
        assertThat(schedulerAnnotation.fixedRate()).isEqualTo(5000);
    }
}