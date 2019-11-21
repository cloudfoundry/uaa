package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.atomic.AtomicLong;

import static javax.servlet.http.HttpServletResponse.SC_SERVICE_UNAVAILABLE;
import static org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter.STATUS_INTERVAL_MS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
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

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;
    private LimitedModeUaaFilter filter;
    private File statusFile;
    private final AtomicLong time = new AtomicLong(System.currentTimeMillis());
    private TimeService timeService;

    @Before
    public void setup() throws Exception {
        timeService = new TimeService() {
            @Override
            public long getCurrentTimeMillis() {
                return time.get();
            }
        };
        request = new MockHttpServletRequest();
        request.addHeader(ACCEPT, "*/*");
        response = new MockHttpServletResponse();
        chain = mock(FilterChain.class);
        filter = new LimitedModeUaaFilter();
        statusFile = File.createTempFile("uaa-limited-mode.", ".status");
    }

    @After
    public void teardown() {
        statusFile.delete();
    }

    @Test
    public void disabled() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
        assertFalse(filter.isEnabled());
    }

    @Test
    public void enabledNoWhitelistPost() throws Exception {
        request.setMethod(POST.name());
        filter.setStatusFile(statusFile);
        filter.doFilterInternal(request, response, chain);
        verifyNoInteractions(chain);
        assertEquals(SC_SERVICE_UNAVAILABLE, response.getStatus());
    }

    @Test
    public void enabledNoWhitelistGet() throws Exception {
        request.setMethod(GET.name());
        filter.setStatusFile(statusFile);
        filter.setPermittedMethods(new HashSet<>(Collections.singletonList(GET.toString())));
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void enabledMatchingUrlPost() throws Exception {
        request.setMethod(POST.name());
        filter.setPermittedEndpoints(Collections.singleton("/oauth/token/**"));
        filter.setStatusFile(statusFile);
        for (String pathInfo : Arrays.asList("/oauth/token", "/oauth/token/alias/something")) {
            setPathInfo(pathInfo, request);
            reset(chain);
            filter.doFilterInternal(request, response, chain);
            verify(chain, times(1)).doFilter(same(request), same(response));
        }
    }

    @Test
    public void enabledNotMatchingPost() throws Exception {
        request.setMethod(POST.name());
        filter.setPermittedEndpoints(Collections.singleton("/oauth/token/**"));
        filter.setStatusFile(statusFile);
        for (String pathInfo : Arrays.asList("/url", "/other/url")) {
            response = new MockHttpServletResponse();
            setPathInfo(pathInfo, request);
            reset(chain);
            filter.doFilterInternal(request, response, chain);
            verifyNoInteractions(chain);
            assertEquals(SC_SERVICE_UNAVAILABLE, response.getStatus());
        }
    }

    @Test
    public void errorIsJson() throws Exception {
        filter.setPermittedEndpoints(Collections.singleton("/oauth/token/**"));
        filter.setStatusFile(statusFile);
        for (String accept : Arrays.asList("application/json", "text/html,*/*")) {
            request = new MockHttpServletRequest();
            response = new MockHttpServletResponse();
            setPathInfo("/not/allowed", request);
            request.setMethod(POST.name());
            request.addHeader(ACCEPT, accept);
            filter.doFilterInternal(request, response, chain);
            assertEquals(SC_SERVICE_UNAVAILABLE, response.getStatus());
            assertEquals(JsonUtils.writeValueAsString(filter.getErrorData()), response.getContentAsString());
        }
    }

    @Test
    public void errorIsNot() throws Exception {
        filter.setPermittedEndpoints(Collections.singleton("/oauth/token/**"));
        filter.setStatusFile(statusFile);
        for (String accept : Arrays.asList("text/html", "text/plain")) {
            request = new MockHttpServletRequest();
            response = new MockHttpServletResponse();
            setPathInfo("/not/allowed", request);
            request.setMethod(POST.name());
            request.addHeader(ACCEPT, accept);
            filter.doFilterInternal(request, response, chain);
            assertEquals(SC_SERVICE_UNAVAILABLE, response.getStatus());
            assertEquals(filter.getErrorData().get("description"), response.getErrorMessage());
        }
    }

    @Test
    public void disableEnableUsesCacheToAvoidFileAccess() {
        File spy = spy(statusFile);
        doCallRealMethod().when(spy).exists();
        filter.setTimeService(timeService);
        filter.setStatusFile(spy);
        assertTrue(filter.isEnabled());
        statusFile.delete();
        for (int i = 0; i < 10; i++) assertTrue(filter.isEnabled());
        time.set(time.get() + STATUS_INTERVAL_MS + 10);
        assertFalse(filter.isEnabled());
        verify(spy, times(2)).exists();
    }

    @Test
    public void settingsFileChangesCache() {
        disableEnableUsesCacheToAvoidFileAccess();
        filter.setStatusFile(null);
        assertFalse(filter.isEnabled());
        assertEquals(0, filter.getLastFileSystemCheck());
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