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

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MetricsUtilTests {
    private static final double DELTA = 1e-15;

    @Test
    public void addToAverage() throws Exception {
        double average = 1.0;
        double avergeCount = 1.0;

        double newAverage = MetricsUtil.addToAverage(avergeCount, average, 1.0, 1.0);
        assertEquals(1.0, newAverage, DELTA);

        newAverage = MetricsUtil.addToAverage(avergeCount, average, 20.0, 20.0);
        assertEquals(1.0, newAverage, DELTA);

        newAverage = MetricsUtil.addToAverage(avergeCount, average, 0, 0);
        assertEquals(1.0, newAverage, DELTA);
    }

    @Test
    public void addAverages() throws Exception {
        double average = 1.0;
        double avergeCount = 1.0;

        double newAverage = MetricsUtil.addAverages(avergeCount, average, 5.0, 1.0);
        assertEquals(1.0, newAverage, DELTA);

        newAverage = MetricsUtil.addAverages(avergeCount, average, 20.0, 1.0);
        assertEquals(1.0, newAverage, DELTA);

        newAverage = MetricsUtil.addAverages(avergeCount, average, 0, 0);
        assertEquals(1.0, newAverage, DELTA);
    }
}