/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.security;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class CsrfAwareEntryPointAndDeniedHandlerTest {

    protected CsrfAwareEntryPointAndDeniedHandler handler = new CsrfAwareEntryPointAndDeniedHandler("/csrf", "/login");
    protected MockHttpServletRequest request = new MockHttpServletRequest();
    protected MockHttpServletResponse response = new MockHttpServletResponse();

    @Before
    public void setUpCsrfAccessDeniedHandler() throws Exception {
        response.setCommitted(false);
    }

    @After
    public void cleanUpAuth() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testHandleWhenCsrfMissing() throws Exception {
        AccessDeniedException ex = new MissingCsrfTokenException("something");
        handler.handle(request, response, ex);
        assertEquals(HttpServletResponse.SC_FOUND, response.getStatus());
        assertSame(request.getAttribute(WebAttributes.ACCESS_DENIED_403), ex);
        assertTrue(response.isCommitted());
        assertEquals("http://localhost/csrf", response.getHeader("Location"));
        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
    }

    @Test
    public void testHandleWhenCsrfMissingForJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        AccessDeniedException ex = new MissingCsrfTokenException("something");
        handler.handle(request, response, ex);
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        assertEquals("{\"error\":\"Expected CSRF token not found. Has your session expired?\"}", response.getContentAsString());
        assertEquals(null, response.getErrorMessage());
    }

    @Test
    public void testHandleWhenNotLoggedIn() throws Exception {
        AccessDeniedException ex = new AccessDeniedException("something");
        handler.handle(request, response, ex);
        assertEquals(HttpServletResponse.SC_FOUND, response.getStatus());
        assertSame(request.getAttribute(WebAttributes.ACCESS_DENIED_403), ex);
        assertTrue(response.isCommitted());
        assertEquals("http://localhost/login", response.getHeader("Location"));
        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY, response.getStatus());
    }

    @Test
    public void testHandleWhenNotLoggedInJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        AccessDeniedException ex = new AccessDeniedException("something");
        handler.handle(request, response, ex);
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        assertEquals("{\"error\":\"something\"}", response.getContentAsString());
        assertEquals(null, response.getErrorMessage());
    }

    @Test(expected = NullPointerException.class)
    public void testNullCsrfUrl() {
        new CsrfAwareEntryPointAndDeniedHandler(null, "/login");
    }

    @Test(expected = NullPointerException.class)
    public void testInvalidCsrfUrl() {
        new CsrfAwareEntryPointAndDeniedHandler("csrf", "/login");
    }

    @Test(expected = NullPointerException.class)
    public void testNullLoginfUrl() {
        new CsrfAwareEntryPointAndDeniedHandler("/csrf", null);
    }

    @Test(expected = NullPointerException.class)
    public void testInvalidLoginUrl() {
        new CsrfAwareEntryPointAndDeniedHandler("/csrf", "login");
    }

}