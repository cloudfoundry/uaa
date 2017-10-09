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


    private TimeService timeService = new TimeServiceImpl();
    private IdleTimer inflight = new IdleTimer();
    private boolean enabled = false;
    Map<String,MetricsQueue> perUriMetrics = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String uriGroup = getUriGroup(request);
        if (enabled && hasText(uriGroup)) {
            RequestMetric metric = RequestMetric.start(request.getRequestURI(), timeService.getCurrentTimeMillis());
            try {
                MetricsAccessor.setCurrent(metric);
                inflight.startRequest();
                filterChain.doFilter(request, response);
            } finally {
                MetricsAccessor.clear();
                inflight.endRequest();
                metric.stop(response.getStatus(), timeService.getCurrentTimeMillis());
                MetricsQueue queue = getMetricsQueue(uriGroup);
                queue.offer(metric);
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
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
    public int getInflightRequests() {
        return inflight.getInflightRequests();
    }

    @ManagedMetric(category = "performance", displayName = "Idle time (ms)")
    public long getIdleTime() {
        return inflight.getIdleTime();
    }

    @ManagedMetric(category = "performance", displayName = "Processing request time (ms)")
    public long getProcessingTime() {
        return inflight.getRunTime() - inflight.getIdleTime();
    }

    @ManagedMetric(category = "performance", displayName = "Total server run time (ms)")
    public long getRunTime() {
        return inflight.getRunTime();
    }

    @ManagedMetric(category = "performance", displayName = "Number of completed requests")
    public long getCompletedRequests() {
        return inflight.getRequestCount();
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
