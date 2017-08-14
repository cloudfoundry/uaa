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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

public class MetricsQueue  {

    public static final int MAX_ENTRIES = 10000;
    public static final int MAX_TIME = 3000;

    ConcurrentLinkedDeque<RequestMetric> queue = new ConcurrentLinkedDeque<>();
    AtomicInteger size = new AtomicInteger(0);
    Map<Integer, RequestMetricTotals> statistics = new ConcurrentHashMap<>();

    public boolean offer(RequestMetric t) {
        if (queue.offer(t)) {
            size.incrementAndGet();
        }
        while (size.decrementAndGet() >= MAX_ENTRIES) {
            queue.removeLast();
        }
        Integer statusCode = t.getStatusCode();
        if (!statistics.containsKey(statusCode)) {
            statistics.putIfAbsent(statusCode, new RequestMetricTotals());
        }
        RequestMetricTotals totals = statistics.get(statusCode);
        totals.add(t.getRequestCompleteTime()-t.getRequestStartTime(), t.getNrOfDatabaseQueries(), t.getDatabaseQueryTime());
        return true;
    }

    public Map<Integer, RequestMetricTotals> getSummary() {
        return statistics;
    }


}
