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

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@ManagedResource(
    objectName="cloudfoundry.identity:name=ServerRequests",
    description = "UAA Performance Metrics"
)
public class UaaMetricsFilter extends OncePerRequestFilter {


    private TimeService timeService = new TimeServiceImpl();
    Map<String,MetricsQueue> perUriMetrics = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (shouldMeasure(request)) {
            RequestMetric metric = RequestMetric.start(request.getRequestURI(), timeService.getCurrentTimeMillis());
            try {
                MetricsAccessor.setCurrent(metric);
                filterChain.doFilter(request, response);
            } finally {
                MetricsAccessor.clear();
                metric.stop(response.getStatus(), timeService.getCurrentTimeMillis());
                MetricsQueue queue = getMetricsQueue(metric.getUri());
                queue.offer(metric);
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    protected MetricsQueue getMetricsQueue(String uri) {
        if (!perUriMetrics.containsKey(uri)) {
            perUriMetrics.putIfAbsent(uri, new MetricsQueue());
        }
        return perUriMetrics.get(uri);
    }

    private boolean shouldMeasure(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri != null && (uri.contains("/resources/") || uri.contains("/vendor/"))) {
            return false;
        } else {
            return true;
        }
    }

    @ManagedMetric(category = "performance", displayName = "Server Request Summary")
    public Map<String, String> getSummary() {
        Map<String, String> data = new HashMap<>();
        perUriMetrics.entrySet().stream().forEach(entry -> data.put(entry.getKey(), JsonUtils.writeValueAsString(entry.getValue().getSummary())));
        return data;
    }

    public TimeService getTimeService() {
        return timeService;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }
}
