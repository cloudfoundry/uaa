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

package org.cloudfoundry.identity.uaa.oauth.token;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;


public class UaaTokenEndpointTests {

    private HashSet<HttpMethod> allowedRequestMethods;
    private UaaTokenEndpoint endpoint;

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private ResponseEntity response;

    @Before
    public void setup() {
        allowedRequestMethods = new HashSet<>(Arrays.asList(POST, GET));
        endpoint = spy(new UaaTokenEndpoint());
        endpoint.setAllowedRequestMethods(allowedRequestMethods);
        response = mock(ResponseEntity.class);
    }

    @Test
    public void allows_get_by_default() throws Exception {
        doReturn(response).when(endpoint).postAccessToken(any(), any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegateGet(mock(Principal.class), emptyMap());
        assertSame(response, result);
    }

    @Test
    public void get_is_disabled() throws Exception {
        exception.expect(HttpRequestMethodNotSupportedException.class);
        endpoint.setAllowQueryString(false);
        ResponseEntity response = mock(ResponseEntity.class);
        doReturn(response).when(endpoint).postAccessToken(any(), any());
        endpoint.doDelegateGet(mock(Principal.class), emptyMap());
    }

    @Test
    public void post_allows_query_string_by_default() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getQueryString()).thenReturn("some-parameter=some-value");
        doReturn(response).when(endpoint).postAccessToken(any(),any());
        ResponseEntity<OAuth2AccessToken> result = endpoint.doDelegatePost(mock(Principal.class), emptyMap(), request);
        assertSame(response, result);
    }

    @Test
    public void setAllowedRequestMethods() throws Exception {
        Set<HttpMethod> methods = (Set<HttpMethod>) ReflectionTestUtils.getField(endpoint, "allowedRequestMethods");
        assertNotNull(methods);
        assertEquals(2, methods.size());
        assertThat(methods, containsInAnyOrder(POST, GET));
    }

    @Test(expected = HttpRequestMethodNotSupportedException.class)
    public void call_to_get_always_throws_super_method() throws Exception {
        UaaTokenEndpoint endpoint = new UaaTokenEndpoint();
        endpoint.setAllowedRequestMethods(allowedRequestMethods);
        endpoint.setAllowQueryString(false);
        try {
            endpoint.getAccessToken(mock(Principal.class), emptyMap());
        } catch (HttpRequestMethodNotSupportedException e) {
            assertEquals("GET", e.getMethod());
            throw e;
        }
    }


    @Test(expected = HttpRequestMethodNotSupportedException.class)
    public void call_to_get_always_throws_override_method() throws Exception {
        UaaTokenEndpoint endpoint = new UaaTokenEndpoint();
        endpoint.setAllowedRequestMethods(allowedRequestMethods);
        endpoint.setAllowQueryString(false);
        try {
            endpoint.doDelegateGet(mock(Principal.class), emptyMap());
        } catch (HttpRequestMethodNotSupportedException e) {
            assertEquals("GET", e.getMethod());
            throw e;
        }
    }
}