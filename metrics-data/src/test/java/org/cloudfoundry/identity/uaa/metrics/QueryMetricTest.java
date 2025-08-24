package org.cloudfoundry.identity.uaa.metrics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class QueryMetricTest {

    private QueryMetric metric;

    @BeforeEach
    void setup() {
        metric = new QueryMetric("query", 1, 5, true);
    }

    @Test
    void getQuery() {
        assertThat(metric.getQuery()).isEqualTo("query");
    }

    @Test
    void isSuccess() {
        assertThat(metric.isIntolerable()).isTrue();
    }

    @Test
    void getRequestStartTime() {
        assertThat(metric.getRequestStartTime()).isOne();
    }

    @Test
    void getRequestCompleteTime() {
        assertThat(metric.getRequestCompleteTime()).isEqualTo(6);
    }
}
