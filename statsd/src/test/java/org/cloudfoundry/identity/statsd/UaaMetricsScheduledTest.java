package org.cloudfoundry.identity.statsd;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@WebAppConfiguration
class UaaMetricsScheduledTest {

    @Autowired
    private UaaMetricsEmitter uaaMetricsEmitter;

    @Test
    void emittingMetrics_Is_Scheduled() throws Exception {
        Scheduled schedulerAnnotation = uaaMetricsEmitter.getClass().getMethod("emitMetrics").getAnnotation(Scheduled.class);
        assertEquals(5000, schedulerAnnotation.fixedRate());
    }
}