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
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jmx.export.notification.NotificationPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.management.Notification;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.metrics.UaaMetricsFilter.FALLBACK;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.readValue;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.*;

public class UaaMetricsFilterTests {

    private UaaMetricsFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;
    private NotificationPublisher publisher;

    @Before
    public void setup() throws Exception {
        filter = spy(new UaaMetricsFilter());
        filter.setEnabled(true);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        publisher = mock(NotificationPublisher.class);
        filter.setNotificationPublisher(publisher);
        chain = mock(FilterChain.class);
    }


    @Test
    public void group_static_content() {
        for (String path : Arrays.asList("/vendor/test", "/resources/test")) {
            setRequestData(path);
            assertEquals("/static-content", filter.getUriGroup(request).getGroup());
            assertNull(MetricsAccessor.getCurrent());
        }
    }

    @Test
    public void enabled_by_default() throws Exception {
        filter = new UaaMetricsFilter();
        assertTrue(filter.isEnabled());
    }

    @Test
    public void per_request_disabled_by_default() throws Exception {
        assertFalse(filter.isPerRequestMetrics());
        performTwoSimpleRequests();
        verify(filter, never()).sendRequestTime(anyString(), anyLong());
    }

    @Test
    public void per_request_enabled() throws Exception {
        filter.setPerRequestMetrics(true);
        assertTrue(filter.isPerRequestMetrics());
        performTwoSimpleRequests();
        verify(filter, times(2)).sendRequestTime(anyString(), anyLong());
    }


    @Test
    public void url_groups_loaded() throws Exception {
        List<UrlGroup> urlGroups = filter.getUrlGroups();
        assertNotNull(urlGroups);
        assertThat(urlGroups.size(), greaterThan(0));
        UrlGroup first = urlGroups.get(0);
        assertEquals("/authenticate/**", first.getPattern());
        assertEquals(1000l, first.getLimit());
        assertEquals("API", first.getCategory());
        assertEquals("/api", first.getGroup());
    }

    @Test
    public void disabled() throws Exception {
        filter.setEnabled(false);
        performTwoSimpleRequests();
        MetricsQueue queue = JsonUtils.readValue(filter.getGlobals(), MetricsQueue.class);
        assertNotNull(queue);
        assertEquals(0, queue.getTotals().getCount());
    }

    public String performTwoSimpleRequests() throws ServletException, IOException {
        String path = "/authenticate/test";
        setRequestData(path);
        for (int status : Arrays.asList(200, 500)) {
            response.setStatus(status);
            filter.doFilterInternal(request, response, chain);
        }
        return path;
    }

    @Test
    public void happy_path() throws Exception {
        filter.setPerRequestMetrics(true);
        String path = performTwoSimpleRequests();
        Map<String, String> summary = filter.getSummary();
        assertNotNull(summary);
        assertFalse(summary.isEmpty());
        assertEquals(2, summary.size());
        for (String uri : Arrays.asList(path, MetricsUtil.GLOBAL_GROUP)) {
            MetricsQueue totals = readValue(summary.get(filter.getUriGroup(request).getGroup()), MetricsQueue.class);
            assertNotNull("URI:"+uri, totals);
            for (StatusCodeGroup status : Arrays.asList(StatusCodeGroup.SUCCESS, StatusCodeGroup.SERVER_ERROR)) {
                RequestMetricSummary total = totals.getDetailed().get(status);
                assertEquals("URI:"+uri, 1, total.getCount());
            }
        }
        assertNull(MetricsAccessor.getCurrent());
        ArgumentCaptor<Notification> argumentCaptor = ArgumentCaptor.forClass(Notification.class);

        verify(publisher, times(2)).sendNotification(argumentCaptor.capture());
        List<Notification> capturedArg = argumentCaptor.getAllValues();
        assertEquals(2, capturedArg.size());
        assertEquals("/api" , capturedArg.get(0).getType());
    }

    @Test
    public void intolerable_request() throws Exception {
        TimeService slowRequestTimeService = new TimeService() {
            long now = System.currentTimeMillis();
            @Override
            public long getCurrentTimeMillis() {
                now += 5000;
                return now;
            }
        };
        for (TimeService timeService : Arrays.asList(slowRequestTimeService, new TimeServiceImpl())) {
            reset(publisher);
            filter = new UaaMetricsFilter();
            filter.setPerRequestMetrics(true);
            filter.setTimeService(timeService);
            filter.setNotificationPublisher(publisher);
            String path = "/authenticate/test";
            setRequestData(path);
            filter.getUriGroup(request).setLimit(1000);
            filter.doFilterInternal(request, response, chain);
            MetricsQueue metricsQueue = filter.getMetricsQueue(filter.getUriGroup(request).getGroup());
            RequestMetricSummary totals = metricsQueue.getTotals();
            assertEquals(1, totals.getCount());
            assertEquals(timeService == slowRequestTimeService ? 1 : 0, totals.getIntolerableCount());

            ArgumentCaptor<Notification> argumentCaptor = ArgumentCaptor.forClass(Notification.class);
            verify(publisher).sendNotification(argumentCaptor.capture());
            Notification capturedArg = argumentCaptor.getValue();
            assertEquals("/api" , capturedArg.getType());
        }
    }

    @Test
    public void idle_counter() throws Exception {
        IdleTimer mockIdleTimer = mock(IdleTimer.class);
        setRequestData("/oauth/token");
        final FilterChain chain = mock(FilterChain.class);
        final UaaMetricsFilter filter = new UaaMetricsFilter();
        filter.setInflight(mockIdleTimer);
        filter.setEnabled(true);

        filter.doFilterInternal(request, response, chain);

        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(mockIdleTimer, times(1)).startRequest();
        verify(mockIdleTimer, times(1)).endRequest();
    }

    public void setRequestData(String requestURI) {
        request.setRequestURI("/uaa" + requestURI);
        request.setPathInfo(requestURI);
        request.setContextPath("/uaa");
        request.setServerName("localhost");
    }

    @Test
    public void deserialize_summary() throws Exception {
        String path = "/some/path";
        setRequestData(path);
        for (int status : Arrays.asList(200,500)) {
            response.setStatus(status);
            filter.doFilterInternal(request, response, chain);
        }
        Map<String, String> summary = filter.getSummary();
        MetricsQueue metricSummary = readValue(summary.get(filter.getUriGroup(request).getGroup()), MetricsQueue.class);
        assertEquals(2, metricSummary.getTotals().getCount());
    }

    @Test
    public void url_groups() {
        request.setServerName("localhost:8080");
        setRequestData("/uaa/authenticate");
        request.setPathInfo("/authenticate");
        request.setContextPath("/uaa");
        assertEquals("/api", filter.getUriGroup(request).getGroup());
    }

    @Test
    public void uri_groups_when_fails_to_load() {
        ReflectionTestUtils.setField(filter, "urlGroups", null);
        request.setContextPath("");
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("/oauth/token/list","/oauth/token/list");
        map.add("/oauth/token/list","/oauth/token/list/some-value");
        map.add("/oauth/token/revoke","/oauth/token/revoke");
        map.add("/oauth/token/revoke","/oauth/token/revoke/some-value");
        map.add("/oauth/token","/oauth/token");
        map.add("/oauth/token","/oauth/token/some-value");
        map.add("/oauth/authorize","/oauth/authorize");
        map.add("/oauth/authorize","/oauth/authorize/some-value");
        map.add("/Users","/Users");
        map.add("/Users","/Users/some-value");
        map.add("/oauth/clients/tx","/oauth/clients/tx");
        map.add("/oauth/clients/tx","/oauth/clients/tx/some-value");
        map.add("/oauth/clients","/oauth/clients");
        map.add("/oauth/clients","/oauth/clients/some-value");
        map.add("/Codes","/Codes");
        map.add("/Codes","/Codes/some-value");
        map.add("/approvals","/approvals");
        map.add("/approvals","/approvals/some-value");
        map.add("/login/callback","/login/callback");
        map.add("/login/callback","/login/callback/some-value");
        map.add("/identity-providers","/identity-providers");
        map.add("/identity-providers","/identity-providers/some-value");
        map.add("/saml/service-providers","/saml/service-providers");
        map.add("/Groups/external","/Groups/external");
        map.add("/Groups/external","/Groups/external/some-value");
        map.add("/Groups/zones","/Groups/zones");
        map.add("/Groups","/Groups");
        map.add("/Groups","/Groups/some/value");
        map.add("/identity-zones","/identity-zones");
        map.add("/identity-zones","/identity-zones/some/value");
        map.add("/saml/login","/saml/login/value");
        map.entrySet().stream().forEach(
            entry -> {
                for (String s : entry.getValue()) {
                    setRequestData(s);
                    assertEquals("Testing URL: "+s, FALLBACK.getGroup(), filter.getUriGroup(request).getGroup());
                }
            }
        );
    }

    @Test
    public void validate_matcher() {
        //validates that patterns that end with /** still match at parent level
        setRequestData("/some/path");
        AntPathRequestMatcher matcher = new AntPathRequestMatcher("/some/path/**");
        assertTrue(matcher.matches(request));
    }
}