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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class QueryMetric {
    private String query;
    private boolean intolerable;
    private long requestStartTime;
    private long requestCompleteTime;

    public QueryMetric(String query, long start, long delta, boolean intolerable) {
        this.query = query;
        this.intolerable = intolerable;
        this.requestStartTime = start;
        this.requestCompleteTime = start + delta;
    }

    public String getQuery() {
        return query;
    }

    public boolean isIntolerable() {
        return intolerable;
    }

    public long getRequestStartTime() {
        return requestStartTime;
    }

    public long getRequestCompleteTime() {
        return requestCompleteTime;
    }
}
