package org.cloudfoundry.identity.uaa.metrics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QueryMetricTest {

    private QueryMetric metric;

    @BeforeEach
    void setup() {
        metric = new QueryMetric("query", 1, 5, true);
    }

    @Test
    void getQuery() {
        assertEquals("query", metric.getQuery());
    }

    @Test
    void isSuccess() {
        assertTrue(metric.isIntolerable());
    }

    @Test
    void getRequestStartTime() {
        assertEquals(1, metric.getRequestStartTime());
    }

    @Test
    void getRequestCompleteTime() {
        assertEquals(6, metric.getRequestCompleteTime());
    }
}