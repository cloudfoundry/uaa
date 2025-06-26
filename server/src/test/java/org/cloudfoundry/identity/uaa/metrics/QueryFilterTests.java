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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class QueryFilterTests {

    private RequestMetric metric;
    private QueryFilter filter;

    @BeforeEach
    void setup() {
        metric = new RequestMetric();
        MetricsAccessor.setCurrent(metric);
        filter = new QueryFilter();
    }

    @AfterEach
    void clear() {
        MetricsAccessor.clear();
    }

    @Test
    void reportUnsuccessfulQuery() {
        long start = System.currentTimeMillis();
        filter.reportFailedQuery("query", null, "name", start, null);
        assertThat(metric.getQueries()).hasSize(1);
        assertThat(metric.getQueries().getFirst().getQuery()).isEqualTo("query");
        assertThat(metric.getQueries().getFirst().getRequestStartTime()).isEqualTo(start);
        assertThat(metric.getQueries().getFirst().isIntolerable()).isFalse();
    }

    @Test
    void reportQuery() {
        filter.reportQuery("query", null, "name", 0, 1);
        assertThat(metric.getQueries()).hasSize(1);
        assertThat(metric.getQueries().getFirst().getQuery()).isEqualTo("query");
        assertThat(metric.getQueries().getFirst().getRequestStartTime()).isZero();
        assertThat(metric.getQueries().getFirst().getRequestCompleteTime()).isOne();
        assertThat(metric.getQueries().getFirst().isIntolerable()).isFalse();
    }

    @Test
    void reportSlowQuery() {
        long delta = filter.getThreshold() + 10;
        filter.reportSlowQuery("query", null, "name", 0, delta);
        assertThat(metric.getQueries()).hasSize(1);
        assertThat(metric.getQueries().getFirst().getQuery()).isEqualTo("query");
        assertThat(metric.getQueries().getFirst().getRequestStartTime()).isZero();
        assertThat(metric.getQueries().getFirst().getRequestCompleteTime()).isEqualTo(delta);
        assertThat(metric.getQueries().getFirst().isIntolerable()).isTrue();
    }

}