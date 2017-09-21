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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.springframework.util.StringUtils.hasText;

@ManagedResource(
    objectName="cloudfoundry.identity:name=ServerRequests",
    description = "UAA Performance Metrics"
)
public class UaaMetricsFilter extends OncePerRequestFilter {

    public static final String GLOBAL_GROUP = "uaa.global.metrics";

    private TimeService timeService = new TimeServiceImpl();
    private IdleTimer inflight = new IdleTimer();
    Map<String,MetricsQueue> perUriMetrics = new ConcurrentHashMap<>();

    public UaaMetricsFilter() {
        perUriMetrics.put(GLOBAL_GROUP, new MetricsQueue());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String uriGroup = getUriGroup(request);
        if (hasText(uriGroup)) {
            RequestMetric metric = RequestMetric.start(request.getRequestURI(), timeService.getCurrentTimeMillis());
            try {
                MetricsAccessor.setCurrent(metric);
                inflight.startRequest();
                filterChain.doFilter(request, response);
            } finally {
                MetricsAccessor.clear();
                inflight.endRequest();
                metric.stop(response.getStatus(), timeService.getCurrentTimeMillis());
                for (String group : Arrays.asList(uriGroup, GLOBAL_GROUP)) {
                    MetricsQueue queue = getMetricsQueue(group);
                    queue.offer(metric);
                }
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

    /**
     *
     * @param request
     * @return null if this request should not be measured.
     */
    protected String getUriGroup(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (hasText(contextPath) && uri != null && uri.startsWith(contextPath)) {
            uri = uri.substring(contextPath.length());
        }
        for (String urlGroup :
            Arrays.asList(
                "/oauth/token/list",
                "/oauth/token/revoke",
                "/oauth/token",
                "/oauth/authorize",
                "/approvals",
                "/Users",
                "/oauth/clients/tx",
                "/oauth/clients",
                "/Codes",
                "/login/callback",
                "/identity-providers",
                "/saml/service-providers",
                "/Groups/external",
                "/Groups/zones",
                "/Groups",
                "/identity-zones",
                "/saml/login"
            )) {

            if (uri.startsWith(urlGroup)) {
                return urlGroup;
            }
        }
        if (uri != null && (uri.startsWith("/resources/") || uri.startsWith("/vendor/"))) {
            return "/static-content";
        } else {
            return uri;
        }
    }

    @ManagedMetric(category = "performance", displayName = "Inflight Requests")
    public long getOutstandingCount() {
        return inflight.getInflightRequests();
    }

    @ManagedMetric(category = "performance", displayName = "Idle time (ms)")
    public long getIdleTime() {
        return inflight.getIdleTime();
    }

    @ManagedMetric(category = "performance", displayName = "Average time per processed request (ms)")
    public double getAverageTimePerRequest() {
        return perUriMetrics.get(GLOBAL_GROUP).getTotals().getAverageTime();
    }

    @ManagedMetric(category = "performance", displayName = "Total server run time (ms)")
    public long getUpTime() {
        return inflight.getRunTime();
    }

    @ManagedMetric(category = "performance", displayName="Completed requests", description = "Number of completed web requests")
    public long getCompletedCount() {
        return perUriMetrics.get(GLOBAL_GROUP).getTotals().getCount();
    }


    @ManagedMetric(category = "performance", displayName = "Server Request Summary")
    public Map<String, String> getSummary() {
        Map<String, String> data = new HashMap<>();
        perUriMetrics.entrySet().stream().forEach(entry -> data.put(entry.getKey(), JsonUtils.writeValueAsString(entry.getValue())));
        return data;
    }

    public TimeService getTimeService() {
        return timeService;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }
}
