/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import java.sql.SQLException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.DispatcherServlet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class RecognizeFailureDispatcherServletTest {


    private MockHttpServletRequest request;
    private RecognizeFailureDispatcherServlet servlet;
    private MockHttpServletResponse response;
    private DispatcherServlet delegate;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        servlet = new RecognizeFailureDispatcherServlet();
        response = new MockHttpServletResponse();
        delegate = mock(DispatcherServlet.class);
    }

    @Test
    public void service_when_failure() throws Exception {
        Mockito.doThrow(new RuntimeException("some app error", new SQLException("db error"))).when(delegate).init(any());
        servlet.setDelegate(delegate);
        servlet.init(mock(ServletConfig.class));
        servlet.service(request, response);
        assertEquals(HttpServletResponse.SC_SERVICE_UNAVAILABLE, response.getStatus());
        verify(delegate, times(1)).init(any());
        verify(delegate, times(0)).service(any(), any());
        assertNotNull(response.getHeader(RecognizeFailureDispatcherServlet.HEADER));
        assertEquals(RecognizeFailureDispatcherServlet.HEADER_MSG, response.getHeader(RecognizeFailureDispatcherServlet.HEADER));
    }
    @Test
    public void service_when_ok() throws Exception {
        DispatcherServlet delegate = mock(DispatcherServlet.class);
        Mockito.doNothing().when(delegate).init(any());
        servlet.setDelegate(delegate);
        servlet.init(mock(ServletConfig.class));
        servlet.service(request, response);
        verify(delegate, times(1)).init(any());
        verify(delegate, times(1)).service(any(), any());
    }


}