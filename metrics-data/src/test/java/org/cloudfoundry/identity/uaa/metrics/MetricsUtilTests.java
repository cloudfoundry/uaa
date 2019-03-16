package org.cloudfoundry.identity.uaa.metrics;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MetricsUtilTests {
    private static final double DELTA = 1e-15;

    @Test
    public void addToAverage() {
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
    public void addAverages() {
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