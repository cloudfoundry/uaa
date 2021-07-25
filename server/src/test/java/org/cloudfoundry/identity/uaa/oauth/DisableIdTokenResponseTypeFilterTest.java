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

package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;

public class DisableIdTokenResponseTypeFilterTest {

    DisableIdTokenResponseTypeFilter filter;
    DisableIdTokenResponseTypeFilter disabledFilter;
    List<String> applyPaths = Arrays.asList("/oauth/authorze", "/**/oauth/authorize");
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    ArgumentCaptor<HttpServletRequest> captor = ArgumentCaptor.forClass(HttpServletRequest.class);
    FilterChain chain = mock(FilterChain.class);

    @Before
    public void setUp() {
        filter = new DisableIdTokenResponseTypeFilter(false, applyPaths);
        disabledFilter = new DisableIdTokenResponseTypeFilter(true, applyPaths);
        request.setPathInfo("/oauth/authorize");
    }

    @Test
    public void testIsIdTokenDisabled() {
        assertFalse(filter.isIdTokenDisabled());
        assertTrue(disabledFilter.isIdTokenDisabled());
    }

    @Test
    public void testApplyPath() {
        shouldApplyPath("/oauth/token", false);
        shouldApplyPath("/someotherpath/uaa/oauth/authorize", true);
        shouldApplyPath("/uaa/oauth/authorize", true);
        shouldApplyPath("/oauth/authorize", true);
        shouldApplyPath(null, false);
        shouldApplyPath("", false);
    }

    public void shouldApplyPath(String path, boolean expectedOutCome) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setPathInfo(path);
        assertEquals(expectedOutCome, filter.applyPath(path));
        assertEquals(expectedOutCome, disabledFilter.applyPath(path));
    }

    @Test
    public void testDoFilterInternal_NO_Response_Type_Parameter() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertSame(request, captor.getValue());
        reset(chain);

        disabledFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertNotSame(request, captor.getValue());
    }

    @Test
    public void testDoFilterInternal_Code_Response_Type_Parameter() throws Exception {
        String responseType = "code";
        request.addParameter(RESPONSE_TYPE, responseType);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertSame(request, captor.getValue());
        reset(chain);
        assertEquals(responseType, captor.getValue().getParameter(RESPONSE_TYPE));
        assertEquals(1, captor.getValue().getParameterMap().get(RESPONSE_TYPE).length);
        assertEquals(responseType, captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]);
        assertEquals(1, captor.getValue().getParameterValues(RESPONSE_TYPE).length);
        assertEquals(responseType, captor.getValue().getParameterValues(RESPONSE_TYPE)[0]);

        disabledFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertNotSame(request, captor.getValue());
        assertEquals(responseType, captor.getValue().getParameter(RESPONSE_TYPE));
        assertEquals(1, captor.getValue().getParameterMap().get(RESPONSE_TYPE).length);
        assertEquals(responseType, captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]);
        assertEquals(1, captor.getValue().getParameterValues(RESPONSE_TYPE).length);
        assertEquals(responseType, captor.getValue().getParameterValues(RESPONSE_TYPE)[0]);
    }

    @Test
    public void testDoFilterInternal_Code_and_IdToken_Response_Type_Parameter() throws Exception {
        String responseType = "code id_token";
        String removedType = "code";
        validate_filter(responseType, removedType);
    }

    @Test
    public void testDoFilterInternal_IdToken_and_Code_Response_Type_Parameter() throws Exception {
        String responseType = "code id_token";
        String removedType = "code";
        validate_filter(responseType, removedType);
    }

    @Test
    public void testDoFilterInternal_Token_and_IdToken_and_Code_Response_Type_Parameter() throws Exception {
        String responseType = "token code id_token";
        String removedType = "token code";
        validate_filter(responseType, removedType);
    }

    public void validate_filter(String responseType, String removedType) throws Exception {
        request.addParameter(RESPONSE_TYPE, responseType);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertSame(request, captor.getValue());
        reset(chain);
        assertEquals(responseType, captor.getValue().getParameter(RESPONSE_TYPE));
        assertEquals(1, captor.getValue().getParameterMap().get(RESPONSE_TYPE).length);
        assertEquals(responseType, captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]);
        assertEquals(1, captor.getValue().getParameterValues(RESPONSE_TYPE).length);
        assertEquals(responseType, captor.getValue().getParameterValues(RESPONSE_TYPE)[0]);

        disabledFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertNotSame(request, captor.getValue());
        assertEquals(removedType, captor.getValue().getParameter(RESPONSE_TYPE));
        assertEquals(1, captor.getValue().getParameterMap().get(RESPONSE_TYPE).length);
        assertEquals(removedType, captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]);
        assertEquals(1, captor.getValue().getParameterValues(RESPONSE_TYPE).length);
        assertEquals(removedType, captor.getValue().getParameterValues(RESPONSE_TYPE)[0]);
    }

}