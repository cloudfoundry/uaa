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

import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;

public class HeaderFilterTest {
    @Test
    public void doFilter() throws Exception {
        FilterChain mockChain = Mockito.mock(FilterChain.class);
        HeaderFilter filter = new HeaderFilter(emptyList());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, mockChain);
        ArgumentCaptor<HttpHeadersFilterRequestWrapper> args = ArgumentCaptor.forClass(HttpHeadersFilterRequestWrapper.class);
        Mockito.verify(mockChain, Mockito.times(1)).doFilter(args.capture(), any());
        Assert.assertTrue(args.getValue() instanceof HttpHeadersFilterRequestWrapper);
    }

    @Test
    public void allows_null_argument() {
        HeaderFilter filter = new HeaderFilter(null);
        assertNotNull(filter.getFilteredHeaderNames());
    }

}