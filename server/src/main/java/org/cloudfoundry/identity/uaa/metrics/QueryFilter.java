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

import org.apache.tomcat.jdbc.pool.interceptor.AbstractQueryReport;

public class QueryFilter extends AbstractQueryReport {

    public QueryFilter() {
        super.setThreshold(2000);
    }

    protected void prepareCall(String arg0, long arg1) {
    }
    protected void prepareStatement(String arg0, long arg1) {
    }
    public void closeInvoked() {
    }

    protected void report(String query, long start, long delta) {
        RequestMetric metric = MetricsAccessor.getCurrent();
        if (metric!=null) {
            metric.addQuery(new QueryMetric(query, start, delta, delta>getThreshold()));
        }
    }


    @Override
    protected String reportFailedQuery(String query, Object[] args,
                                       String name, long start, Throwable t) {
        String sql = super.reportFailedQuery(query, args, name, start, t);
        long delta = System.currentTimeMillis() - start;
        report(sql, start, delta);
        return sql;
    }

    @Override
    protected String reportQuery(String query, Object[] args,
                                 String name, long start, long delta) {
        String sql = super.reportQuery(query, args, name, start, delta);
        report(sql, start, delta);
        return sql;
    }

    @Override
    protected String reportSlowQuery(String query, Object[] args,
                                     String name, long start, long delta) {
        return reportQuery(query, args, name, start, delta);
    }

}
