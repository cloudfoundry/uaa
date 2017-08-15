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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import java.util.Arrays;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class UaaMetricsFilterTests {

    private UaaMetricsFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;

    @Before
    public void setup() throws Exception {
        filter = new UaaMetricsFilter();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = Mockito.mock(FilterChain.class);
    }


    @Test
    public void ignore_certain_paths() throws Exception {
        for (String path : Arrays.asList("/vendor/test", "/resources/test")) {
            request.setRequestURI(path);
            filter.doFilterInternal(request, response, chain);
            assertNotNull(filter.getSummary());
            assertTrue(filter.getSummary().isEmpty());
            assertNull(MetricsAccessor.getCurrent());
        }
    }

    @Test
    public void happy_path() throws Exception {
        String path = "/some/path";
        request.setRequestURI(path);
        for (int status : Arrays.asList(200,500)) {
            response.setStatus(status);
            filter.doFilterInternal(request, response, chain);
        }
        Map<String, String> summary = filter.getSummary();
        assertNotNull(summary);
        assertFalse(summary.isEmpty());
        assertEquals(1, summary.size());
        Map<Integer, RequestMetricSummary> totals = JsonUtils.readValue(summary.get(path), new TypeReference<Map<Integer, RequestMetricSummary>>() {});
        assertNotNull(totals);
        for (int status : Arrays.asList(200,500)) {
            RequestMetricSummary total = totals.get(status);
            assertEquals(1, total.getCount());
        }
        assertNull(MetricsAccessor.getCurrent());
    }
}