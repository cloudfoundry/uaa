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
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static java.util.Collections.emptyMap;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.NOT_ACCEPTABLE;


public class UaaTokenEndpointTests {

    private HashSet<HttpMethod> allowedRequestMethods;
    private UaaTokenEndpoint endpoint;

    @Before
    public void setup() {
        allowedRequestMethods = new HashSet<>(Arrays.asList(POST, GET));
        endpoint = new UaaTokenEndpoint();
        endpoint.setAllowedRequestMethods(allowedRequestMethods);
    }

    @Test
    public void setAllowedRequestMethods() throws Exception {
        Set<HttpMethod> methods = (Set<HttpMethod>) ReflectionTestUtils.getField(endpoint, "allowedRequestMethods");
        assertNotNull(methods);
        assertEquals(1, methods.size());
        assertEquals(POST, methods.toArray()[0]);
    }

    @Test(expected = HttpRequestMethodNotSupportedException.class)
    public void call_to_get_always_throws_super_method() throws Exception {
        UaaTokenEndpoint endpoint = new UaaTokenEndpoint();
        endpoint.setAllowedRequestMethods(allowedRequestMethods);
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
        try {
            endpoint.doDelegateGet(mock(Principal.class), emptyMap());
        } catch (HttpRequestMethodNotSupportedException e) {
            assertEquals("GET", e.getMethod());
            throw e;
        }
    }

    @Test
    public void call_to_post_with_query_string_throws_not_acceptable() throws Exception {
        ResponseEntity<OAuth2Exception> result = endpoint.handleHttpRequestMethodNotSupportedException(new HttpRequestMethodNotSupportedException("POST"));
        assertNotNull(result);
        assertEquals(NOT_ACCEPTABLE, result.getStatusCode());
    }

}