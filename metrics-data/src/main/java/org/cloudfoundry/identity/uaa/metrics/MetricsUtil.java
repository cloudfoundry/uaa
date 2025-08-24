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

public final class MetricsUtil {
    public static final String GLOBAL_GROUP = "uaa.global.metrics";

    // Utility classes should not have public constructors
    private MetricsUtil() {
        throw new IllegalStateException("Utility class");
    }

    public static double addAverages(double oldCount,
            double oldAverage,
            double newCount,
            double newAverage) {
        if (newCount == 0) {
            return oldAverage;
        }
        return
                (oldCount / (newCount + oldCount) * oldAverage) +
                        (newCount / (newCount + oldCount) * newAverage);
    }

    public static double addToAverage(double oldCount,
            double oldAverage,
            double newCount,
            double newTotalTime) {
        if (newCount == 0) {
            return oldAverage;
        }
        double newAverage = newTotalTime / newCount;
        return
                (oldCount / (newCount + oldCount) * oldAverage) +
                        (newCount / (newCount + oldCount) * newAverage);
    }

    public static class MutableLong {
        long value;

        public MutableLong(long value) {
            this.value = value;
        }

        public long get() {
            return value;
        }

        public void set(long value) {
            this.value = value;
        }

        public void add(long value) {
            this.value += value;
        }

        @Override
        public String toString() {
            return Long.toString(get());
        }
    }

    public static class MutableDouble {
        double value;

        public MutableDouble(double value) {
            this.value = value;
        }

        public double get() {
            return value;
        }

        public void set(double value) {
            this.value = value;
        }

        public void add(double value) {
            this.value += value;
        }

        @Override
        public String toString() {
            return Double.toString(get());
        }
    }
}
