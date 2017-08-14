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

public class QueryMetric {
    private String query;
    private boolean success;
    private long requestStartTime;
    private long requestCompleteTime;

    public QueryMetric(String query, long start, long delta, boolean success) {
        this.query = query;
        this.success = success;
        this.requestStartTime = start;
        this.requestCompleteTime = start + delta;
    }

    public String getQuery() {
        return query;
    }

    public boolean isSuccess() {
        return success;
    }

    public long getRequestStartTime() {
        return requestStartTime;
    }

    public long getRequestCompleteTime() {
        return requestCompleteTime;
    }
}
