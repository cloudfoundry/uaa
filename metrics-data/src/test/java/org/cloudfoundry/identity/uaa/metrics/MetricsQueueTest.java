package org.cloudfoundry.identity.uaa.metrics;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class MetricsQueueTest {

    private static final long MAX_TIME = 3000;
    private static final double DELTA = 1e-15;

    private MetricsQueue queue;

    private final UrlGroup uriGroup = new UrlGroup()
            .setGroup("/uri")
            .setLimit(MAX_TIME)
            .setPattern("/uri")
            .setCategory("test");

    @BeforeEach
    void setup() {
        queue = new MetricsQueue();
        RequestMetric metric = RequestMetric.start("uri", uriGroup, 0);
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.stop(200, 2);
        queue.offer(metric);
        metric = RequestMetric.start("uri", uriGroup, 0);
        metric.addQuery(new QueryMetric("query1", 0, 5, true));
        metric.stop(200, MAX_TIME + 1);
        queue.offer(metric);
        metric = RequestMetric.start("uri", uriGroup, 0);
        metric.addQuery(new QueryMetric("query1", 0, 2, false));
        metric.stop(500, 5);
        queue.offer(metric);
    }

    @Test
    void summary() {
        validateMetricsQueue(queue);
    }

    @Test
    void totals() {
        RequestMetricSummary summary = queue.getTotals();
        assertThat(summary).isNotNull();
        assertThat(summary.getCount()).isEqualTo(3);
        assertThat(summary.getIntolerableCount()).isOne();
        assertThat(summary.getAverageTime()).isCloseTo(((double) (MAX_TIME + 3 + 5)) / 3.0, within(DELTA));
        assertThat(summary.getAverageIntolerableTime()).isCloseTo((double) MAX_TIME + 1, within(DELTA));
        assertThat(summary.getDatabaseQueryCount()).isEqualTo(3);
        assertThat(summary.getAverageDatabaseQueryTime()).isCloseTo(3, within(DELTA));
        assertThat(summary.getDatabaseIntolerableQueryCount()).isEqualTo(2);
        assertThat(summary.getAverageDatabaseIntolerableQueryTime()).isCloseTo(3.5, within(DELTA));
    }

    @Test
    void json_serialize() {
        String json = JsonUtils.writeValueAsString(queue);
        Map<String, Object> object = JsonUtils.readValue(json, new TypeReference<Map<String, Object>>() {
        });
        assertThat(object).hasSize(3);
        MetricsQueue deserialized = JsonUtils.readValue(json, MetricsQueue.class);
        assertThat(deserialized).isNotNull();
        validateMetricsQueue(deserialized);
    }

    @Test
    void overflowLimitRespected() throws Exception {
        RequestMetric metric = RequestMetric.start("uri", uriGroup, 0);
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.stop(200, 2);
        Runnable add10Metrics = () -> {
            for (int i = 0; i < 10; i++) {
                queue.offer(metric);
            }
        };
        Thread[] threads = new Thread[5];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(add10Metrics);
        }
        for (int i = 0; i < threads.length; i++) {
            threads[i].start();
        }
        for (int i = 0; i < threads.length; i++) {
            threads[i].join();
        }
        assertThat(queue.getLastRequests()).hasSizeLessThanOrEqualTo(MetricsQueue.MAX_ENTRIES);
    }

    @Test
    void offer() {
        queue = new MetricsQueue();
        RequestMetric metric = RequestMetric.start("uri", uriGroup, 0);
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.addQuery(new QueryMetric("query2", 0, 2, false));
        metric.stop(200, 2);
        queue.offer(metric);
        RequestMetricSummary totals = queue.getTotals();
        assertThat(totals.getDatabaseQueryCount()).isEqualTo(3);
        assertThat(totals.getDatabaseIntolerableQueryCount()).isEqualTo(2);
    }

    private static void validateMetricsQueue(MetricsQueue queue) {
        Map<StatusCodeGroup, RequestMetricSummary> summary = queue.getDetailed();
        assertThat(summary).hasSize(2);
        RequestMetricSummary twoHundredResponses = summary.get(StatusCodeGroup.SUCCESS);
        assertThat(twoHundredResponses).isNotNull();
        assertThat(twoHundredResponses.getCount()).isEqualTo(2);
        assertThat(twoHundredResponses.getIntolerableCount()).isOne();
        assertThat(twoHundredResponses.getAverageTime()).isCloseTo((double) (MAX_TIME + 3) / 2.0, within(DELTA));
        assertThat(twoHundredResponses.getAverageIntolerableTime()).isCloseTo(MAX_TIME + 1, within(DELTA));
        assertThat(twoHundredResponses.getDatabaseQueryCount()).isEqualTo(2);
        assertThat(twoHundredResponses.getAverageDatabaseQueryTime()).isCloseTo(3.5, within(DELTA));

        RequestMetricSummary fiveHundredResponses = summary.get(StatusCodeGroup.SERVER_ERROR);
        assertThat(fiveHundredResponses).isNotNull();
        assertThat(fiveHundredResponses.getCount()).isOne();
        assertThat(fiveHundredResponses.getIntolerableCount()).isZero();
        assertThat(fiveHundredResponses.getAverageTime()).isCloseTo(5, within(DELTA));
        assertThat(fiveHundredResponses.getAverageIntolerableTime()).isCloseTo(0, within(DELTA));
        assertThat(fiveHundredResponses.getDatabaseQueryCount()).isOne();
        assertThat(fiveHundredResponses.getAverageDatabaseQueryTime()).isCloseTo(2, within(DELTA));
        assertThat(fiveHundredResponses.getDatabaseIntolerableQueryCount()).isZero();
        assertThat(fiveHundredResponses.getAverageDatabaseIntolerableQueryTime()).isCloseTo(0, within(DELTA));

        assertThat(queue.getLastRequests()).hasSize(3);
    }
}
