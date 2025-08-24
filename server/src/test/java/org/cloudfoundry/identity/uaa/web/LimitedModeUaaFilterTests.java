package org.cloudfoundry.identity.uaa.web;
import jakarta.servlet.http.HttpServletResponse;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicLong;

import static jakarta.servlet.http.HttpServletResponse.SC_SERVICE_UNAVAILABLE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter.STATUS_INTERVAL_MS;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

public class LimitedModeUaaFilterTests {

    private MockHttpServletRequest mockHttpServletRequest;
    private MockHttpServletResponse mockHttpServletResponse;
    private FilterChain mockFilterChain;
    private LimitedModeUaaFilter filter;
    private File statusFile;
    private final AtomicLong time = new AtomicLong(System.currentTimeMillis());
    private TimeService timeService;

    @BeforeEach
    void setUp() throws Exception {
        timeService = new TimeService() {
            @Override
            public long getCurrentTimeMillis() {
                return time.get();
            }
        };
        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.addHeader(ACCEPT, "*/*");
        mockHttpServletResponse = new MockHttpServletResponse();
        mockFilterChain = mock(FilterChain.class);
        filter = new LimitedModeUaaFilter();
        statusFile = Files.createTempFile("uaa-limited-mode.", ".status").toFile();
    }

    @AfterEach
    void tearDown() {
        statusFile.delete();
    }

    @Test
    void disabled() throws Exception {
        filter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
        assertThat(filter.isEnabled()).isFalse();
    }

    @Test
    void enabledNoWhitelistPost() throws Exception {
        mockHttpServletRequest.setMethod(POST.name());
        filter.setStatusFile(statusFile);
        filter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verifyNoInteractions(mockFilterChain);
        assertThat(mockHttpServletResponse.getStatus()).isEqualTo(SC_SERVICE_UNAVAILABLE);
    }

    @Test
    void enabledNoWhitelistGet() throws Exception {
        mockHttpServletRequest.setMethod(GET.name());
        filter.setStatusFile(statusFile);
        filter.setPermittedMethods(new HashSet<>(Collections.singletonList(GET.toString())));
        filter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
        verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
    }

    @Test
    void enabledMatchingUrlPost() throws Exception {
        mockHttpServletRequest.setMethod(POST.name());
        filter.setPermittedEndpoints(Collections.singleton("/oauth/token/**"));
        filter.setStatusFile(statusFile);
        for (String pathInfo : Arrays.asList("/oauth/token", "/oauth/token/alias/something")) {
            setPathInfo(pathInfo, mockHttpServletRequest);
            reset(mockFilterChain);
            filter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
            verify(mockFilterChain, times(1)).doFilter(same(mockHttpServletRequest), same(mockHttpServletResponse));
        }
    }

    @Test
    void enabledNotMatchingPost() throws Exception {
        mockHttpServletRequest.setMethod(POST.name());
        filter.setPermittedEndpoints(Collections.singleton("/oauth/token/**"));
        filter.setStatusFile(statusFile);
        for (String pathInfo : Arrays.asList("/url", "/other/url")) {
            mockHttpServletResponse = new MockHttpServletResponse();
            setPathInfo(pathInfo, mockHttpServletRequest);
            reset(mockFilterChain);
            filter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
            verifyNoInteractions(mockFilterChain);
            assertThat(mockHttpServletResponse.getStatus()).isEqualTo(SC_SERVICE_UNAVAILABLE);
        }
    }

    @Test
    void errorIsJson() throws Exception {
        filter.setPermittedEndpoints(Collections.singleton("/oauth/token/**"));
        filter.setStatusFile(statusFile);
        for (String accept : Arrays.asList("application/json", "text/html,*/*")) {
            mockHttpServletRequest = new MockHttpServletRequest();
            mockHttpServletResponse = new MockHttpServletResponse();
            setPathInfo("/not/allowed", mockHttpServletRequest);
            mockHttpServletRequest.setMethod(POST.name());
            mockHttpServletRequest.addHeader(ACCEPT, accept);
            filter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
            assertThat(mockHttpServletResponse.getStatus()).isEqualTo(SC_SERVICE_UNAVAILABLE);
            assertThat(mockHttpServletResponse.getContentAsString()).isEqualTo(JsonUtils.writeValueAsString(filter.getErrorData()));
        }
    }

    @Test
    void errorIsNot() throws Exception {
        filter.setPermittedEndpoints(Collections.singleton("/oauth/token/**"));
        filter.setStatusFile(statusFile);
        for (String accept : Arrays.asList("text/html", "text/plain")) {
            mockHttpServletRequest = new MockHttpServletRequest();
            mockHttpServletResponse = new MockHttpServletResponse();
            setPathInfo("/not/allowed", mockHttpServletRequest);
            mockHttpServletRequest.setMethod(POST.name());
            mockHttpServletRequest.addHeader(ACCEPT, accept);
            filter.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, mockFilterChain);
            assertThat(mockHttpServletResponse.getStatus()).isEqualTo(SC_SERVICE_UNAVAILABLE);
            assertThat(mockHttpServletResponse.getErrorMessage()).isEqualTo(filter.getErrorData().get("description"));
        }
    }

    @Test
    void disableEnableUsesCacheToAvoidFileAccess() {
        File spy = spy(statusFile);
        doCallRealMethod().when(spy).exists();
        filter.setTimeService(timeService);
        filter.setStatusFile(spy);
        assertThat(filter.isEnabled()).isTrue();
        statusFile.delete();
        for (int i = 0; i < 10; i++) {
            assertThat(filter.isEnabled()).isTrue();
        }
        time.set(time.get() + STATUS_INTERVAL_MS + 10);
        assertThat(filter.isEnabled()).isFalse();
        verify(spy, times(2)).exists();
    }

    @Test
    void settingsFileChangesCache() {
        disableEnableUsesCacheToAvoidFileAccess();
        filter.setStatusFile(null);
        assertThat(filter.isEnabled()).isFalse();
        assertThat(filter.getLastFileSystemCheck()).isZero();
    }

    public static void setPathInfo(
            final String pathInfo,
            final MockHttpServletRequest request) {
        request.setServletPath("");
        request.setPathInfo(pathInfo);
        request.setContextPath("/uaa");
        request.setRequestURI(request.getContextPath() + request.getPathInfo());
    }
}