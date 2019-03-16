package org.cloudfoundry.identity.statsd;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest
@WebAppConfiguration
public class UaaMetricsScheduledTest {

    @Autowired
    private UaaMetricsEmitter uaaMetricsEmitter;

    @Test
    public void emittingMetrics_Is_Scheduled() throws Exception {
        Scheduled schedulerAnnotation = uaaMetricsEmitter.getClass().getMethod("emitMetrics").getAnnotation(Scheduled.class);
        Assert.assertEquals(5000, schedulerAnnotation.fixedRate());
    }
}