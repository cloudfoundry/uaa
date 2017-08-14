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

import java.util.concurrent.atomic.AtomicLong;

public class RequestMetricTotals {
    AtomicLong count = new AtomicLong(0);
    AtomicLong totalTime = new AtomicLong(0);
    AtomicLong intolerableCount = new AtomicLong(0);
    AtomicLong intolerableTime = new AtomicLong(0);
    AtomicLong databaseQueryCount = new AtomicLong(0);
    AtomicLong databaseQueryTime = new AtomicLong(0);

    public void add(long time, long dbQueries, long dbTime) {
        count.incrementAndGet();
        totalTime.addAndGet(time);
        if (time > MetricsQueue.MAX_TIME) {
            intolerableCount.incrementAndGet();
            intolerableTime.addAndGet(time);
        }
        databaseQueryCount.addAndGet(dbQueries);
        databaseQueryTime.addAndGet(dbTime);
    }

    public long getCount() {
        return count.get();
    }

    public long getTotalTime() {
        return totalTime.get();
    }

    public long getIntolerableCount() {
        return intolerableCount.get();
    }

    public long getIntolerableTime() {
        return intolerableTime.get();
    }

    public long getDatabaseQueryCount() {
        return databaseQueryCount.get();
    }

    public long getDatabaseQueryTime() {
        return databaseQueryTime.get();
    }
}
