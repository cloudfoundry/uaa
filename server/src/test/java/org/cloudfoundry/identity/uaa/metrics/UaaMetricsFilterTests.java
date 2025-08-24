package org.cloudfoundry.identity.uaa.metrics;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jmx.export.notification.NotificationPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.management.Notification;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.metrics.UaaMetricsFilter.FALLBACK;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.readValue;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class UaaMetricsFilterTests {

    private UaaMetricsFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;
    private NotificationPublisher publisher;

    @BeforeEach
    void setup() throws Exception {
        filter = spy(new UaaMetricsFilter(true, false, new TimeServiceImpl()));
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        publisher = mock(NotificationPublisher.class);
        filter.setNotificationPublisher(publisher);
        chain = mock(FilterChain.class);
    }

    @Test
    void group_static_content() {
        for (String path : Arrays.asList("/vendor/test", "/resources/test")) {
            setRequestData(path);
            assertThat(filter.getUriGroup(request).getGroup()).isEqualTo("/static-content");
            assertThat(MetricsAccessor.getCurrent()).isNull();
        }
    }

    @Test
    void per_request_disabled_by_default() throws Exception {
        performTwoSimpleRequests();
        verify(filter, never()).sendRequestTime(anyString(), anyLong());
    }

    @Test
    void per_request_enabled() throws Exception {
        filter = spy(new UaaMetricsFilter(true, true, new TimeServiceImpl()));
        performTwoSimpleRequests();
        verify(filter, times(2)).sendRequestTime(anyString(), anyLong());
    }

    @Test
    void url_groups_loaded() throws Exception {
        List<UrlGroup> urlGroups = filter.getUrlGroups();
        assertThat(urlGroups).isNotEmpty();
        UrlGroup first = urlGroups.getFirst();
        assertThat(first.getPattern()).isEqualTo("/authenticate/**");
        assertThat(first.getLimit()).isEqualTo(1000L);
        assertThat(first.getCategory()).isEqualTo("API");
        assertThat(first.getGroup()).isEqualTo("/api");
    }

    @Test
    void disabled() throws Exception {
        filter = spy(new UaaMetricsFilter(false, false, new TimeServiceImpl()));
        performTwoSimpleRequests();
        MetricsQueue queue = JsonUtils.readValue(filter.getGlobals(), MetricsQueue.class);
        assertThat(queue).isNotNull();
        assertThat(queue.getTotals().getCount()).isZero();
    }

    String performTwoSimpleRequests() throws ServletException, IOException {
        String path = "/authenticate/test";
        setRequestData(path);
        for (int status : Arrays.asList(200, 500)) {
            response.setStatus(status);
            filter.doFilterInternal(request, response, chain);
        }
        return path;
    }

    @Test
    void happy_path() throws Exception {
        filter = spy(new UaaMetricsFilter(true, true, new TimeServiceImpl()));
        filter.setNotificationPublisher(publisher);
        String path = performTwoSimpleRequests();
        Map<String, String> summary = filter.getSummary();
        assertThat(summary).hasSize(2);
        for (String uri : Arrays.asList(path, MetricsUtil.GLOBAL_GROUP)) {
            MetricsQueue totals = readValue(summary.get(filter.getUriGroup(request).getGroup()), MetricsQueue.class);
            assertThat(totals).as("URI:" + uri).isNotNull();
            for (StatusCodeGroup status : Arrays.asList(StatusCodeGroup.SUCCESS, StatusCodeGroup.SERVER_ERROR)) {
                RequestMetricSummary total = totals.getDetailed().get(status);
                assertThat(total.getCount()).as("URI:" + uri).isOne();
            }
        }
        assertThat(MetricsAccessor.getCurrent()).isNull();
        ArgumentCaptor<Notification> argumentCaptor = ArgumentCaptor.forClass(Notification.class);

        verify(publisher, times(2)).sendNotification(argumentCaptor.capture());
        List<Notification> capturedArg = argumentCaptor.getAllValues();
        assertThat(capturedArg).hasSize(2);
        assertThat(capturedArg.getFirst().getType()).isEqualTo("/api");
    }

    @Test
    void intolerable_request() throws Exception {
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
            filter = new UaaMetricsFilter(true, true, timeService);
            filter.setNotificationPublisher(publisher);
            String path = "/authenticate/test";
            setRequestData(path);
            filter.getUriGroup(request).setLimit(1000);
            filter.doFilterInternal(request, response, chain);
            MetricsQueue metricsQueue = filter.getMetricsQueue(filter.getUriGroup(request).getGroup());
            RequestMetricSummary totals = metricsQueue.getTotals();
            assertThat(totals.getCount()).isOne();
            assertThat(totals.getIntolerableCount()).isEqualTo(timeService == slowRequestTimeService ? 1 : 0);

            ArgumentCaptor<Notification> argumentCaptor = ArgumentCaptor.forClass(Notification.class);
            verify(publisher).sendNotification(argumentCaptor.capture());
            Notification capturedArg = argumentCaptor.getValue();
            assertThat(capturedArg.getType()).isEqualTo("/api");
        }
    }

    @Test
    void idle_counter() throws Exception {
        IdleTimer mockIdleTimer = mock(IdleTimer.class);
        setRequestData("/oauth/token");
        final FilterChain chain = mock(FilterChain.class);
        final UaaMetricsFilter filter = new UaaMetricsFilter(true, false, new TimeServiceImpl());
        ReflectionTestUtils.setField(filter, "inflight", mockIdleTimer);

        filter.doFilterInternal(request, response, chain);

        verify(chain, times(1)).doFilter(same(request), same(response));
        verify(mockIdleTimer, times(1)).startRequest();
        verify(mockIdleTimer, times(1)).endRequest();
    }

    void setRequestData(String requestURI) {
        request.setRequestURI("/uaa" + requestURI);
        request.setPathInfo(requestURI);
        request.setContextPath("/uaa");
        request.setServerName("localhost");
    }

    @Test
    void deserialize_summary() throws Exception {
        String path = "/some/path";
        setRequestData(path);
        for (int status : Arrays.asList(200, 500)) {
            response.setStatus(status);
            filter.doFilterInternal(request, response, chain);
        }
        Map<String, String> summary = filter.getSummary();
        MetricsQueue metricSummary = readValue(summary.get(filter.getUriGroup(request).getGroup()), MetricsQueue.class);
        assertThat(metricSummary.getTotals().getCount()).isEqualTo(2);
    }

    @Test
    void url_groups() {
        request.setServerName("localhost:8080");
        setRequestData("/uaa/authenticate");
        request.setPathInfo("/authenticate");
        request.setContextPath("/uaa");
        assertThat(filter.getUriGroup(request).getGroup()).isEqualTo("/api");
    }

    @Test
    void uri_groups_when_fails_to_load() {
        ReflectionTestUtils.setField(filter, "urlGroups", null);
        request.setContextPath("");
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("/oauth/token/list", "/oauth/token/list");
        map.add("/oauth/token/list", "/oauth/token/list/some-value");
        map.add("/oauth/token/revoke", "/oauth/token/revoke");
        map.add("/oauth/token/revoke", "/oauth/token/revoke/some-value");
        map.add("/oauth/token", "/oauth/token");
        map.add("/oauth/token", "/oauth/token/some-value");
        map.add("/oauth/authorize", "/oauth/authorize");
        map.add("/oauth/authorize", "/oauth/authorize/some-value");
        map.add("/Users", "/Users");
        map.add("/Users", "/Users/some-value");
        map.add("/oauth/clients/tx", "/oauth/clients/tx");
        map.add("/oauth/clients/tx", "/oauth/clients/tx/some-value");
        map.add("/oauth/clients", "/oauth/clients");
        map.add("/oauth/clients", "/oauth/clients/some-value");
        map.add("/Codes", "/Codes");
        map.add("/Codes", "/Codes/some-value");
        map.add("/approvals", "/approvals");
        map.add("/approvals", "/approvals/some-value");
        map.add("/login/callback", "/login/callback");
        map.add("/login/callback", "/login/callback/some-value");
        map.add("/identity-providers", "/identity-providers");
        map.add("/identity-providers", "/identity-providers/some-value");
        map.add("/Groups/external", "/Groups/external");
        map.add("/Groups/external", "/Groups/external/some-value");
        map.add("/Groups/zones", "/Groups/zones");
        map.add("/Groups", "/Groups");
        map.add("/Groups", "/Groups/some/value");
        map.add("/identity-zones", "/identity-zones");
        map.add("/identity-zones", "/identity-zones/some/value");
        map.add("/saml/login", "/saml/login/value");
        map.forEach((key, value) -> {
            for (String s : value) {
                setRequestData(s);
                assertThat(filter.getUriGroup(request).getGroup()).as("Testing URL: " + s).isEqualTo(FALLBACK.getGroup());
            }
        });
    }

    @Test
    void validate_matcher() {
        //validates that patterns that end with /** still match at parent level
        setRequestData("/some/path");
        AntPathRequestMatcher matcher = new AntPathRequestMatcher("/some/path/**");
        assertThat(matcher.matches(request)).isTrue();
    }
}
