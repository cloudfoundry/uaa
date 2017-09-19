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

package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import java.util.Arrays;
import java.util.HashSet;

import static javax.servlet.http.HttpServletResponse.SC_SERVICE_UNAVAILABLE;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

public class DegradedModeUaaFilterTests {

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;
    private DegradedModeUaaFilter filter;

    @Before
    public void setup() throws Exception {
        request = new MockHttpServletRequest();
        request.addHeader(ACCEPT, "*/*");
        response = new MockHttpServletResponse();
        chain = mock(FilterChain.class);
        filter = new DegradedModeUaaFilter();
    }

    public void setPathInfo(String pathInfo) {
        request.setServletPath("");
        request.setPathInfo(pathInfo);
        request.setContextPath("/uaa");
        request.setRequestURI(request.getContextPath()+request.getPathInfo());
    }

    @Test
    public void disabled() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void enabled_no_whitelist_post() throws Exception {
        request.setMethod(POST.name());
        filter.setEnabled(true);
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(chain);
        assertEquals(SC_SERVICE_UNAVAILABLE, response.getStatus());
    }

    @Test
    public void enabled_no_whitelist_get() throws Exception {
        request.setMethod(GET.name());
        filter.setEnabled(true);
        filter.setPermittedMethods(new HashSet<>(Arrays.asList(GET.toString())));
        filter.doFilterInternal(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void enabled_matching_url_post() throws Exception {
        request.setMethod(POST.name());
        filter.setPermittedEndpoints(new HashSet(Arrays.asList("/oauth/token/**")));
        filter.setEnabled(true);
        for (String pathInfo : Arrays.asList("/oauth/token", "/oauth/token/alias/something")) {
            setPathInfo(pathInfo);
            reset(chain);
            filter.doFilterInternal(request, response, chain);
            verify(chain, times(1)).doFilter(same(request), same(response));
        }
    }

    @Test
    public void enabled_not_matching_post() throws Exception {
        request.setMethod(POST.name());
        filter.setPermittedEndpoints(new HashSet(Arrays.asList("/oauth/token/**")));
        filter.setEnabled(true);
        for (String pathInfo : Arrays.asList("/url", "/other/url")) {
            response = new MockHttpServletResponse();
            setPathInfo(pathInfo);
            reset(chain);
            filter.doFilterInternal(request, response, chain);
            verifyZeroInteractions(chain);
            assertEquals(SC_SERVICE_UNAVAILABLE, response.getStatus());
        }
    }

    @Test
    public void error_is_json() throws Exception {
        filter.setPermittedEndpoints(new HashSet(Arrays.asList("/oauth/token/**")));
        filter.setEnabled(true);
        for (String accept : Arrays.asList("application/json", "text/html,*/*")) {
            request = new MockHttpServletRequest();
            response = new MockHttpServletResponse();
            setPathInfo("/not/allowed");
            request.setMethod(POST.name());
            request.addHeader(ACCEPT, accept);
            filter.doFilterInternal(request, response, chain);
            assertEquals(SC_SERVICE_UNAVAILABLE, response.getStatus());
            assertEquals(JsonUtils.writeValueAsString(filter.getErrorData()), response.getContentAsString());
        }
    }

    @Test
    public void error_is_not() throws Exception {
        filter.setPermittedEndpoints(new HashSet(Arrays.asList("/oauth/token/**")));
        filter.setEnabled(true);
        for (String accept : Arrays.asList("text/html", "text/plain")) {
            request = new MockHttpServletRequest();
            response = new MockHttpServletResponse();
            setPathInfo("/not/allowed");
            request.setMethod(POST.name());
            request.addHeader(ACCEPT, accept);
            filter.doFilterInternal(request, response, chain);
            assertEquals(SC_SERVICE_UNAVAILABLE, response.getStatus());
            assertEquals(filter.getErrorData().get("description"), response.getErrorMessage());
        }
    }

}