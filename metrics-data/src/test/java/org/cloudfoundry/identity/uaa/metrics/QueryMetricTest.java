package org.cloudfoundry.identity.uaa.metrics;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class QueryMetricTest {

    private QueryMetric metric;

    @Before
    public void setup() throws Exception {
        metric = new QueryMetric("query", 1, 5, true);
    }

    @Test
    public void getQuery() {
        assertEquals("query", metric.getQuery());
    }

    @Test
    public void isSuccess() {
        assertTrue(metric.isIntolerable());
    }

    @Test
    public void getRequestStartTime() {
        assertEquals(1, metric.getRequestStartTime());
    }

    @Test
    public void getRequestCompleteTime() {
        assertEquals(6, metric.getRequestCompleteTime());
    }
}