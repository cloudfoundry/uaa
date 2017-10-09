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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class MetricsQueueTests {

    private MetricsQueue queue;

    @Before
    public void setup() throws Exception {
        queue = new MetricsQueue();
        RequestMetric metric = RequestMetric.start("uri",0);
        metric.addQuery(new QueryMetric("query1", 0, 2, true));
        metric.stop(200, 2);
        queue.offer(metric);
        metric = RequestMetric.start("uri",0);
        metric.addQuery(new QueryMetric("query1", 0, 5, true));
        metric.stop(200, MetricsQueue.MAX_TIME+1);
        queue.offer(metric);
        metric = RequestMetric.start("uri",0);
        metric.addQuery(new QueryMetric("query1", 0, 2, false));
        metric.stop(500, 5);
        queue.offer(metric);
    }

    @After
    public void teardown() throws Exception {
        MetricsAccessor.clear();
    }

    @Test
    public void getSummary() throws Exception {
        Map<Integer, RequestMetricSummary> summary = queue.getSummary();
        assertNotNull(summary);
        assertEquals(2, summary.size());
        RequestMetricSummary twoHundredResponses = summary.get(200);
        assertNotNull(twoHundredResponses);
        assertEquals(2, twoHundredResponses.getCount());
        assertEquals(1, twoHundredResponses.getIntolerableCount());
        assertEquals(MetricsQueue.MAX_TIME+3, twoHundredResponses.getTotalTime());
        assertEquals(MetricsQueue.MAX_TIME+1, twoHundredResponses.getIntolerableTime());
        assertEquals(2, twoHundredResponses.getDatabaseQueryCount());
        assertEquals(7, twoHundredResponses.getDatabaseQueryTime());

        RequestMetricSummary fiveHundredResponses = summary.get(500);
        assertNotNull(fiveHundredResponses);
        assertEquals(1, fiveHundredResponses.getCount());
        assertEquals(0, fiveHundredResponses.getIntolerableCount());
        assertEquals(5, fiveHundredResponses.getTotalTime());
        assertEquals(0, fiveHundredResponses.getIntolerableTime());
        assertEquals(1, fiveHundredResponses.getDatabaseQueryCount());
        assertEquals(2, fiveHundredResponses.getDatabaseQueryTime());
        assertEquals(1, fiveHundredResponses.getDatabaseFailedQueryCount());
        assertEquals(2, fiveHundredResponses.getDatabaseFailedQueryTime());
    }

}