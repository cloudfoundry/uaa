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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.export.notification.NotificationPublisher;
import org.springframework.jmx.export.notification.NotificationPublisherAware;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.yaml.snakeyaml.Yaml;

import javax.management.Notification;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@ManagedResource(
    objectName="cloudfoundry.identity:name=ServerRequests",
    description = "UAA Performance Metrics"
)
public class UaaMetricsFilter extends OncePerRequestFilter implements UaaMetrics, NotificationPublisherAware {
    public static final int MAX_TIME = 3000;
    public static final UrlGroup FALLBACK = new UrlGroup()
        .setCategory("Unknown")
        .setGroup("/unknown")
        .setLimit(MAX_TIME)
        .setPattern("/**");

    private static Logger logger = LoggerFactory.getLogger(UaaMetricsFilter.class);

    private TimeService timeService = new TimeServiceImpl();
    private IdleTimer inflight = new IdleTimer();
    private Map<String,MetricsQueue> perUriMetrics = new ConcurrentHashMap<>();
    private LinkedHashMap<AntPathRequestMatcher, UrlGroup> urlGroups;
    private boolean enabled = true;
    private boolean perRequestMetrics = false;

    private NotificationPublisher notificationPublisher;

    public UaaMetricsFilter() throws IOException {
        perUriMetrics.put(MetricsUtil.GLOBAL_GROUP, new MetricsQueue());
        urlGroups = new LinkedHashMap<>();
        List<UrlGroup> groups = getUrlGroups();
        groups.stream().forEach(
            group -> urlGroups.put(new AntPathRequestMatcher(group.getPattern()), group)
        );
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        UrlGroup uriGroup = enabled ? getUriGroup(request) : null;
        if (uriGroup != null) {
            RequestMetric metric = RequestMetric.start(request.getRequestURI(), uriGroup, timeService.getCurrentTimeMillis());
            try {
                MetricsAccessor.setCurrent(metric);
                inflight.startRequest();
                filterChain.doFilter(request, response);
            } finally {
                MetricsAccessor.clear();
                inflight.endRequest();
                metric.stop(response.getStatus(), timeService.getCurrentTimeMillis());
                if (isPerRequestMetrics()) {
                    sendRequestTime(uriGroup.getGroup(), metric.getRequestCompleteTime() - metric.getRequestStartTime());
                }
                for (String group : Arrays.asList(uriGroup.getGroup(), MetricsUtil.GLOBAL_GROUP)) {
                    MetricsQueue queue = getMetricsQueue(group);
                    queue.offer(metric);
                }
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
    protected UrlGroup getUriGroup(HttpServletRequest request) {
        if (urlGroups!=null) {
            String uri = request.getRequestURI();
            for (Map.Entry<AntPathRequestMatcher, UrlGroup> entry : urlGroups.entrySet()) {
                if (entry.getKey().matches(request)) {
                    UrlGroup group = entry.getValue();
                    logger.debug(String.format("Successfully matched URI: %s to a group: %s", uri, group.getGroup()));
                    return group;
                }
            }
            return FALLBACK;
        } else {
            return FALLBACK;
        }
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Inflight Requests")
    public long getInflightCount() {
        return inflight.getInflightRequests();
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Idle time (ms)")
    public long getIdleTime() {
        return inflight.getIdleTime();
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Total server run time (ms)")
    public long getUpTime() {
        return inflight.getRunTime();
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Server Requests for all URI Groups")
    public Map<String, String> getSummary() {
        Map<String, String> data = new HashMap<>();
        perUriMetrics.entrySet().stream().forEach(entry -> data.put(entry.getKey(), JsonUtils.writeValueAsString(entry.getValue())));
        return data;
    }

    @Override
    @ManagedMetric(category = "performance", displayName = "Global Server Request Summary")
    public String getGlobals() {
        return JsonUtils.writeValueAsString(perUriMetrics.get(MetricsUtil.GLOBAL_GROUP));
    }

    public TimeService getTimeService() {
        return timeService;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }

    public List<UrlGroup> getUrlGroups() throws IOException {
        ClassPathResource resource = new ClassPathResource("performance-url-groups.yml");
        Yaml yaml = new Yaml();
        List<Map<String,Object>> load = (List<Map<String, Object>>) yaml.load(resource.getInputStream());
        return load.stream().map(map -> UrlGroup.from(map)).collect(Collectors.toList());
    }

    public void sendRequestTime(String urlGroup, long time) {
        if(notificationPublisher != null) {
            Notification note = new Notification(urlGroup, time, 0);
            notificationPublisher.sendNotification(note);
        } else {
            logger.debug("notification publisher not found by UaaMetricsFilter");
        }
    }

    @Override
    public void setNotificationPublisher(NotificationPublisher notificationPublisher) {
        this.notificationPublisher = notificationPublisher;
    }

    public boolean isPerRequestMetrics() {
        return perRequestMetrics;
    }

    public void setPerRequestMetrics(boolean perRequestMetrics) {
        this.perRequestMetrics = perRequestMetrics;
    }

    public void setInflight(IdleTimer inflight) {
        this.inflight = inflight;
    }
}
