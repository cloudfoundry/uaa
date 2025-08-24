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
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.metrics.MetricsUtil.MutableDouble;
import org.cloudfoundry.identity.uaa.metrics.MetricsUtil.MutableLong;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.metrics.MetricsUtil.addAverages;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(NON_NULL)
public class MetricsQueue {

    public static final int MAX_ENTRIES = 5;

    private ConcurrentLinkedDeque<RequestMetric> queue;
    private Map<StatusCodeGroup, RequestMetricSummary> statistics;

    public MetricsQueue() {
        this(null, null);
    }

    @JsonCreator
    public MetricsQueue(@JsonProperty("lastRequests") ConcurrentLinkedDeque<RequestMetric> queue,
            @JsonProperty("detailed") Map<StatusCodeGroup, RequestMetricSummary> statistics) {
        this.queue = ofNullable(queue).orElse(new ConcurrentLinkedDeque<>());
        this.statistics = ofNullable(statistics).orElse(new ConcurrentHashMap<>());
    }

    public boolean offer(RequestMetric metric) {
        queue.offer(metric);
        //remove earliest entries
        while (queue.size() > MAX_ENTRIES) {
            queue.removeFirst();
        }

        StatusCodeGroup statusCode = StatusCodeGroup.valueOf(metric.getStatusCode());
        if (!statistics.containsKey(statusCode)) {
            statistics.putIfAbsent(statusCode, new RequestMetricSummary());
        }
        RequestMetricSummary totals = statistics.get(statusCode);
        long time = metric.getRequestCompleteTime() - metric.getRequestStartTime();
        totals.add(time,
                time < metric.getUriGroup().getLimit(),
                metric.getNrOfDatabaseQueries(),
                metric.getDatabaseQueryTime(),
                metric.getQueries().stream().filter(QueryMetric::isIntolerable).count(),
                metric.getQueries().stream().filter(QueryMetric::isIntolerable).mapToLong(q -> q.getRequestCompleteTime() - q.getRequestStartTime()).sum()
        );
        return true;
    }

    public Map<StatusCodeGroup, RequestMetricSummary> getDetailed() {
        return statistics;
    }


    public ConcurrentLinkedDeque<RequestMetric> getLastRequests() {
        return queue;
    }

    @JsonProperty("summary")
    public RequestMetricSummary getTotals() {
        MutableLong count = new MutableLong(0);
        MutableDouble averageTime = new MutableDouble(0);
        MutableLong intolerableCount = new MutableLong(0);
        MutableDouble averageIntolerableTime = new MutableDouble(0);
        MutableLong databaseQueryCount = new MutableLong(0);
        MutableDouble averageDatabaseQueryTime = new MutableDouble(0);
        MutableLong databaseIntolerableQueryCount = new MutableLong(0);
        MutableDouble averageDatabaseIntolerableQueryTime = new MutableDouble(0);
        statistics.forEach((key, summary) -> {
            averageTime.set(addAverages(count.get(),
                    averageTime.get(),
                    summary.getCount(),
                    summary.getAverageTime())
            );
            count.add(summary.getCount());

            averageIntolerableTime.set(addAverages(intolerableCount.get(),
                    averageIntolerableTime.get(),
                    summary.getIntolerableCount(),
                    summary.getAverageIntolerableTime())
            );
            intolerableCount.add(summary.getIntolerableCount());

            averageDatabaseQueryTime.set(addAverages(databaseQueryCount.get(),
                    averageDatabaseQueryTime.get(),
                    summary.getDatabaseQueryCount(),
                    summary.getAverageDatabaseQueryTime()
            )
            );
            databaseQueryCount.add(summary.getDatabaseQueryCount());

            averageDatabaseIntolerableQueryTime.set(addAverages(databaseIntolerableQueryCount.get(),
                    averageDatabaseIntolerableQueryTime.get(),
                    summary.getDatabaseIntolerableQueryCount(),
                    summary.getAverageDatabaseIntolerableQueryTime()
            )
            );
            databaseIntolerableQueryCount.add(summary.getDatabaseIntolerableQueryCount());

        });
        return new RequestMetricSummary(count.get(),
                averageTime.get(),
                intolerableCount.get(),
                averageIntolerableTime.get(),
                databaseQueryCount.get(),
                averageDatabaseQueryTime.get(),
                databaseIntolerableQueryCount.get(),
                averageDatabaseIntolerableQueryTime.get());
    }

}
