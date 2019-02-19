/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.metrics;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class MetricsQueueTests {

    private static final long MAX_TIME = 3000;
    private static final double DELTA = 1e-15;

    private MetricsQueue queue;

    private UrlGroup uriGroup = new UrlGroup()
        .setGroup("/uri")
        .setLimit(MAX_TIME)
        .setPattern("/uri")
        .setCategory("test");

    @Before
    public void setup() throws Exception {
        queue = new MetricsQueue();
        RequestMetric metric = RequestMetric.start("uri", uriGroup,0);
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.stop(200, 2);
        queue.offer(metric);
        metric = RequestMetric.start("uri",uriGroup, 0);
        metric.addQuery(new QueryMetric("query1", 0, 5, true));
        metric.stop(200, MAX_TIME+1);
        queue.offer(metric);
        metric = RequestMetric.start("uri", uriGroup,0);
        metric.addQuery(new QueryMetric("query1", 0, 2, false));
        metric.stop(500, 5);
        queue.offer(metric);
    }

    @Test
    public void summary() throws Exception {
        validateMetricsQueue(queue);
    }

    @Test
    public void totals() throws Exception {
        RequestMetricSummary summary = queue.getTotals();
        assertNotNull(summary);
        assertEquals(3, summary.getCount());
        assertEquals(1, summary.getIntolerableCount());
        assertEquals(((double)(MAX_TIME+3+5)) / 3.0, summary.getAverageTime(), DELTA);
        assertEquals((double)MAX_TIME+1, summary.getAverageIntolerableTime(), DELTA);
        assertEquals(3, summary.getDatabaseQueryCount());
        assertEquals(3, summary.getAverageDatabaseQueryTime(), DELTA);
        assertEquals(2, summary.getDatabaseIntolerableQueryCount());
        assertEquals(3.5, summary.getAverageDatabaseIntolerableQueryTime(), DELTA);

    }

    public void validateMetricsQueue(MetricsQueue queue) {
        Map<StatusCodeGroup, RequestMetricSummary> summary = queue.getDetailed();
        assertNotNull(summary);
        assertEquals(2, summary.size());
        RequestMetricSummary twoHundredResponses = summary.get(StatusCodeGroup.SUCCESS);
        assertNotNull(twoHundredResponses);
        assertEquals(2, twoHundredResponses.getCount());
        assertEquals(1, twoHundredResponses.getIntolerableCount());
        assertEquals((double)(MAX_TIME+3) / 2.0, twoHundredResponses.getAverageTime(), DELTA);
        assertEquals(MAX_TIME+1, twoHundredResponses.getAverageIntolerableTime(), DELTA);
        assertEquals(2, twoHundredResponses.getDatabaseQueryCount());
        assertEquals(3.5, twoHundredResponses.getAverageDatabaseQueryTime(), DELTA);

        RequestMetricSummary fiveHundredResponses = summary.get(StatusCodeGroup.SERVER_ERROR);
        assertNotNull(fiveHundredResponses);
        assertEquals(1, fiveHundredResponses.getCount());
        assertEquals(0, fiveHundredResponses.getIntolerableCount());
        assertEquals(5, fiveHundredResponses.getAverageTime(), DELTA);
        assertEquals(0, fiveHundredResponses.getAverageIntolerableTime(), DELTA);
        assertEquals(1, fiveHundredResponses.getDatabaseQueryCount());
        assertEquals(2, fiveHundredResponses.getAverageDatabaseQueryTime(), DELTA);
        assertEquals(0, fiveHundredResponses.getDatabaseIntolerableQueryCount());
        assertEquals(0, fiveHundredResponses.getAverageDatabaseIntolerableQueryTime(), DELTA);

        assertEquals(3, queue.getLastRequests().size());
    }

    @Test
    public void json_serialize() throws Exception {
        String json = JsonUtils.writeValueAsString(queue);
        Map<String,Object> object = JsonUtils.readValue(json, new TypeReference<Map<String, Object>>() {});
        assertEquals(3, object.size());
        MetricsQueue deserialized = JsonUtils.readValue(json, MetricsQueue.class);
        validateMetricsQueue(deserialized);
    }

    @Test
    public void overflow_limit_respected() throws Exception {
        RequestMetric metric = RequestMetric.start("uri",uriGroup,0);
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.stop(200, 2);
        Runnable add10Metrics = () -> {
            for (int i=0; i<10; i++) {
                queue.offer(metric);
            }
        };
        Thread[] threads = new Thread[5];
        for (int i=0; i<threads.length; i++) {
            threads[i] = new Thread(add10Metrics);
        }
        for (int i=0; i<threads.length; i++) {
            threads[i].start();
        }
        for (int i=0; i<threads.length; i++) {
            threads[i].join();
        }
        assertThat(queue.getLastRequests().size(), Matchers.lessThanOrEqualTo(MetricsQueue.MAX_ENTRIES));

    }

    @Test
    public void offer() throws Exception {
        queue = new MetricsQueue();
        RequestMetric metric = RequestMetric.start("uri",uriGroup,0);
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.addQuery(new QueryMetric("query2", 0, 2, false));
        metric.stop(200, 2);
        queue.offer(metric);
        RequestMetricSummary totals = queue.getTotals();
        assertEquals(3, totals.getDatabaseQueryCount());
        assertEquals(2, totals.getDatabaseIntolerableQueryCount());
    }

}