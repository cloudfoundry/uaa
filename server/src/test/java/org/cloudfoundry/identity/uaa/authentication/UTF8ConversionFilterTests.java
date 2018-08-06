/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class UTF8ConversionFilterTests {

    private MockHttpServletResponse response;
    private MockHttpServletRequest request;
    private FilterChain chain;
    private UTF8ConversionFilter filter;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = mock(FilterChain.class);
        filter = new UTF8ConversionFilter();
    }

    public void verifyChain(int count) throws IOException, ServletException {
        filter.doFilter(request, response, chain);
        verify(chain, times(count)).doFilter(any(), any());
        if (count==0) {
            assertEquals(400, response.getStatus());
        }
    }



    @Test
    public void validateParamsAndContinue() throws Exception {
        verifyChain(1);
    }

    @Test
    public void nullCharactersInSingleValueParams_1() throws Exception {
        request.setParameter("test", new String(new char[] {'a','b','\u0000'}));
        verifyChain(0);
    }

    @Test
    public void nullCharactersInSingleValueParams_2() throws Exception {
        request.setParameter("test", new String(new char[] {'a','b',(char)0}));
        verifyChain(0);
    }
}