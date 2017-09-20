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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;
import static java.util.Optional.ofNullable;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(NON_NULL)
public class MetricsQueue  {

    public static final int MAX_ENTRIES = 5;
    public static final int MAX_TIME = 3000;

    private ConcurrentLinkedDeque<RequestMetric> queue;
    private Map<Integer, RequestMetricSummary> statistics;

    public MetricsQueue() {
        this(null,null);
    }

    @JsonCreator
    public MetricsQueue(@JsonProperty("lastRequests") ConcurrentLinkedDeque<RequestMetric> queue,
                        @JsonProperty("summary") Map<Integer, RequestMetricSummary> statistics) {
        this.queue = ofNullable(queue).orElse(new ConcurrentLinkedDeque<>());
        this.statistics = ofNullable(statistics).orElse(new ConcurrentHashMap<>());
    }

    public boolean offer(RequestMetric metric) {
        queue.offer(metric);
        //remove eariest entries
        while (queue.size() > MAX_ENTRIES) {
            queue.removeLast();
        }

        Integer statusCode = metric.getStatusCode();
        if (!statistics.containsKey(statusCode)) {
            statistics.putIfAbsent(statusCode, new RequestMetricSummary());
        }
        RequestMetricSummary totals = statistics.get(statusCode);
        totals.add(metric.getRequestCompleteTime()- metric.getRequestStartTime(),
                   metric.getNrOfDatabaseQueries(),
                   metric.getDatabaseQueryTime(),
                   metric.getQueries().stream().filter(q -> !q.isSuccess()).count(),
                   metric.getQueries().stream().filter(q -> !q.isSuccess()).mapToLong(q -> q.getRequestCompleteTime()-q.getRequestStartTime()).sum()
        );
        return true;
    }

    public Map<Integer, RequestMetricSummary> getSummary() {
        return statistics;
    }


    public ConcurrentLinkedDeque<RequestMetric> getLastRequests() {
        return queue;
    }

    @JsonIgnore
    public RequestMetricSummary getTotals() {
        AtomicLong count = new AtomicLong(0);
        AtomicLong totalTime = new AtomicLong(0);
        AtomicLong intolerableCount = new AtomicLong(0);
        AtomicLong intolerableTime = new AtomicLong(0);
        AtomicLong databaseQueryCount = new AtomicLong(0);
        AtomicLong databaseQueryTime = new AtomicLong(0);
        AtomicLong databaseFailedQueryCount = new AtomicLong(0);
        AtomicLong databaseFailedQueryTime = new AtomicLong(0);
        statistics.entrySet().stream().forEach( s -> {
            RequestMetricSummary summary = s.getValue();
            count.addAndGet(summary.getCount());
            totalTime.addAndGet(summary.getTotalTime());
            intolerableCount.addAndGet(summary.getIntolerableCount());
            intolerableTime.addAndGet(summary.getIntolerableTime());
            databaseQueryCount.addAndGet(summary.getDatabaseQueryCount());
            databaseQueryTime.addAndGet(summary.getDatabaseQueryTime());
            databaseFailedQueryCount.addAndGet(summary.getDatabaseFailedQueryCount());
            databaseFailedQueryTime.addAndGet(summary.getDatabaseFailedQueryTime());

        });
        return new RequestMetricSummary(count,
                                        totalTime,
                                        intolerableCount,
                                        intolerableTime,
                                        databaseQueryCount,
                                        databaseQueryTime,
                                        databaseFailedQueryCount,
                                        databaseFailedQueryTime);
    }

}
