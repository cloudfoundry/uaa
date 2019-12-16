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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class QueryFilterTests {

    private RequestMetric metric;
    private QueryFilter filter;

    @Before
    public void setup() {
        metric = new RequestMetric();
        MetricsAccessor.setCurrent(metric);
        filter = new QueryFilter();
    }

    @After
    public void clear() {
        MetricsAccessor.clear();
    }


    @Test
    public void reportUnsuccessfulQuery() {
        long start = System.currentTimeMillis();
        filter.reportFailedQuery("query", null, "name", start, null);
        assertNotNull(metric.getQueries());
        assertEquals(1, metric.getQueries().size());
        assertEquals("query", metric.getQueries().get(0).getQuery());
        assertEquals(start, metric.getQueries().get(0).getRequestStartTime());
        assertFalse(metric.getQueries().get(0).isIntolerable());
    }

    @Test
    public void reportQuery() {
        filter.reportQuery("query", null, "name", 0, 1);
        assertNotNull(metric.getQueries());
        assertEquals(1, metric.getQueries().size());
        assertEquals("query", metric.getQueries().get(0).getQuery());
        assertEquals(0, metric.getQueries().get(0).getRequestStartTime());
        assertEquals(1, metric.getQueries().get(0).getRequestCompleteTime());
        assertFalse(metric.getQueries().get(0).isIntolerable());
    }

    @Test
    public void reportSlowQuery() {
        long delta = filter.getThreshold() + 10;
        filter.reportSlowQuery("query", null, "name", 0, delta);
        assertNotNull(metric.getQueries());
        assertEquals(1, metric.getQueries().size());
        assertEquals("query", metric.getQueries().get(0).getQuery());
        assertEquals(0, metric.getQueries().get(0).getRequestStartTime());
        assertEquals(delta, metric.getQueries().get(0).getRequestCompleteTime());
        assertTrue(metric.getQueries().get(0).isIntolerable());
    }

}