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

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class QueryMetricTests {

    private QueryMetric metric;

    @Before
    public void setup() throws Exception {
        metric = new QueryMetric("query", 1, 5, true);
    }

    @Test
    public void getQuery() throws Exception {
        assertEquals("query", metric.getQuery());
    }

    @Test
    public void isSuccess() throws Exception {
        assertEquals(true, metric.isIntolerable());
    }

    @Test
    public void getRequestStartTime() throws Exception {
        assertEquals(1, metric.getRequestStartTime());
    }

    @Test
    public void getRequestCompleteTime() throws Exception {
        assertEquals(6, metric.getRequestCompleteTime());
    }

}