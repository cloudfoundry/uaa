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
import com.fasterxml.jackson.annotation.JsonProperty;

import static org.cloudfoundry.identity.uaa.metrics.MetricsUtil.addToAverage;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RequestMetricSummary {
    long count = 0;
    double averageTime = 0;
    long intolerableCount = 0;
    double averageIntolerableTime = 0;
    long databaseQueryCount = 0;
    double averageDatabaseQueryTime = 0;
    long databaseFailedQueryCount = 0;
    double averageDatabaseFailedQueryTime = 0;

    public RequestMetricSummary() {
    }

    @JsonCreator
    public RequestMetricSummary(@JsonProperty("count") long count,
                                @JsonProperty("averageTime") double averageTime,
                                @JsonProperty("intolerableCount") long intolerableCount,
                                @JsonProperty("averageIntolerableTime") double averageIntolerableTime,
                                @JsonProperty("databaseQueryCount") long databaseQueryCount,
                                @JsonProperty("averageDatabaseQueryTime") double averageDatabaseQueryTime,
                                @JsonProperty("databaseFailedQueryCount") long databaseFailedQueryCount,
                                @JsonProperty("averageDatabaseFailedQueryTime") double averageDatabaseFailedQueryTime) {
        this.count = count;
        this.averageTime = averageTime;
        this.intolerableCount = intolerableCount;
        this.averageIntolerableTime = averageIntolerableTime;
        this.databaseQueryCount = databaseQueryCount;
        this.averageDatabaseQueryTime = averageDatabaseQueryTime;
        this.databaseFailedQueryCount = databaseFailedQueryCount;
        this.averageDatabaseFailedQueryTime = averageDatabaseFailedQueryTime;
    }

    public synchronized void add(long time, long dbQueries, long dbTime, long failedDbQueries, long failedDbQueryTime) {
        averageTime = addToAverage(count, averageTime, 1, time);
        count++;
        if (time > MetricsQueue.MAX_TIME) {
            averageIntolerableTime = addToAverage(intolerableCount, averageIntolerableTime, 1, time);
            ++intolerableCount;
        }
        averageDatabaseQueryTime = addToAverage(databaseQueryCount, averageDatabaseQueryTime, dbQueries, dbTime);
        databaseQueryCount += dbQueries;

        averageDatabaseFailedQueryTime = addToAverage(databaseFailedQueryCount, averageDatabaseFailedQueryTime, failedDbQueries, failedDbQueryTime);
        databaseFailedQueryCount += failedDbQueries;
    }

    public long getCount() {
        return count;
    }

    public double getAverageTime() {
        return averageTime;
    }

    public long getIntolerableCount() {
        return intolerableCount;
    }

    public double getAverageIntolerableTime() {
        return averageIntolerableTime;
    }

    public long getDatabaseQueryCount() {
        return databaseQueryCount;
    }

    public double getAverageDatabaseQueryTime() {
        return averageDatabaseQueryTime;
    }

    public long getDatabaseFailedQueryCount() {
        return databaseFailedQueryCount;
    }

    public double getAverageDatabaseFailedQueryTime() {
        return averageDatabaseFailedQueryTime;
    }
}
