/*******************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.security.web;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 */
public class UaaRequestMatcherTests {

    private MockHttpServletRequest request(String path, String accept, String... parameters) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/ctx");
        request.setRequestURI("/ctx" + path);
        if (accept != null) {
            request.addHeader("Accept", accept);
        }
        for (int i = 0; i < parameters.length; i += 2) {
            String key = parameters[i];
            String value = parameters[i + 1];
            request.addParameter(key, value);
        }
        return request;
    }

    @Test
    public void pathMatcherMatchesExpectedPaths() {
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        assertTrue(matcher.matches(request("/somePath", null)));
        assertTrue(matcher.matches(request("/somePath", "application/json")));
        assertTrue(matcher.matches(request("/somePath", "application/html")));
        assertTrue(matcher.matches(request("/somePath/aak", null)));
        assertTrue(matcher.matches(request("/somePath?blah=x", null)));
        // We don't actually want this for anything but it's a consequence of
        // using substring matching
        assertTrue(matcher.matches(request("/somePathOrOther", null)));
    }

    @Test
    public void pathMatcherMatchesExpectedPathsAndAcceptHeaderNull() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        assertTrue(matcher.matches(request("/somePath", null)));
    }

    @Test
    public void pathMatcherMatchesExpectedPathsAndMatchingAcceptHeader() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        assertTrue(matcher.matches(request("/somePath", "application/json")));
    }

    @Test
    public void pathMatcherMatchesExpectedPathsAndNonMatchingAcceptHeader() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        assertFalse(matcher.matches(request("/somePath", "application/html")));
    }

    @Test
    public void pathMatcherMatchesExpectedPathsAndRequestParameters() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        matcher.setParameters(Collections.singletonMap("response_type", "token"));
        assertTrue(matcher.matches(request("/somePath", null, "response_type", "token")));
    }

    @Test
    public void pathMatcherMatchesExpectedPathsAndMultipleRequestParameters() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put("source", "foo");
        params.put("response_type", "token");
        matcher.setParameters(params);
        assertFalse(matcher.matches(request("/somePath", null, "response_type", "token")));
        assertTrue(matcher.matches(request("/somePath", null, "response_type", "token", "source", "foo")));
    }

    @Test
    public void pathMatcherMatchesExpectedPathsAndEmptyParameters() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        matcher.setParameters(Collections.singletonMap("code", ""));
        assertTrue(matcher.matches(request("/somePath", null, "code", "FOO")));
        assertFalse(matcher.matches(request("/somePath", null)));
    }

    @Test
    public void pathMatcherMatchesExpectedPathsAndRequestParametersWithAcceptHeader() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        matcher.setParameters(Collections.singletonMap("response_type", "token"));
        assertTrue(matcher.matches(request("/somePath", "application/json", "response_type", "token")));
    }

    @Test
    public void pathMatcherMatchesExpectedPathsAndRequestParametersWithNonMatchingAcceptHeader() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        matcher.setParameters(Collections.singletonMap("response_type", "token"));
        assertFalse(matcher.matches(request("/somePath", "application/html", "response_type", "token")));
    }

    @Test
    public void pathMatcherMatchesWithMultipleAccepts() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON.toString()));
        assertTrue(matcher
                        .matches(request("/somePath",
                                        String.format("%s,%s", MediaType.APPLICATION_JSON.toString(),
                                                        MediaType.APPLICATION_XML.toString()))));
    }

    @Test
    public void pathMatcherMatchesWithMultipleAcceptTargets() {
        // Accept only JSON
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setAccept(Arrays.asList(MediaType.APPLICATION_JSON.toString(),
                        MediaType.APPLICATION_FORM_URLENCODED.toString()));
        assertTrue(matcher
                        .matches(request("/somePath",
                                        String.format("%s,%s", MediaType.APPLICATION_JSON.toString(),
                                                        MediaType.APPLICATION_XML.toString()))));
    }

    @Test
    public void pathMatcherMatchesWithSingleHeader() {
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setHeaders(Collections.singletonMap("Authorization", Collections.singletonList("Basic")));
        MockHttpServletRequest testRequest = request(
                        "/somePath",
                        String.format("%s,%s", MediaType.APPLICATION_JSON.toString(),
                                        MediaType.APPLICATION_XML.toString()));
        testRequest.addHeader("Authorization", "Basic abc");
        assertTrue(matcher
                        .matches(testRequest));
    }

    @Test
    public void pathMatcherDoesNotMatchInvalidHeader() {
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        matcher.setHeaders(Collections.singletonMap("Authorization", Collections.singletonList("Basic")));
        MockHttpServletRequest testRequest = request(
                        "/somePath",
                        String.format("%s,%s", MediaType.APPLICATION_JSON.toString(),
                                        MediaType.APPLICATION_XML.toString()));
        assertFalse(matcher
                        .matches(testRequest));
    }

    @Test
    public void pathMatcherMatchesOneOfMultipleHeaders() {
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        Map<String, List<String>> configMap = new HashMap<String, List<String>>();
        configMap.put("Authorization", Arrays.asList(new String[] { "Basic", "Bearer" }));
        matcher.setHeaders(configMap);
        MockHttpServletRequest testRequest = request(
                        "/somePath",
                        String.format("%s,%s", MediaType.APPLICATION_JSON.toString(),
                                        MediaType.APPLICATION_XML.toString()));
        testRequest.addHeader("Authorization", "Basic abc");
        assertFalse(matcher
                        .matches(testRequest));
    }

    @Test
    public void pathMatcherDoesNotMatchOneOfMultipleHeaders() {
        UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
        Map<String, List<String>> configMap = new HashMap<String, List<String>>();
        configMap.put("Authorization", Arrays.asList(new String[] { "Basic", "Bearer" }));
        matcher.setHeaders(configMap);
        MockHttpServletRequest testRequest = request(
                        "/somePath",
                        String.format("%s,%s", MediaType.APPLICATION_JSON.toString(),
                                        MediaType.APPLICATION_XML.toString()));
        testRequest.addHeader("Authorization", "non matching header value");
        assertFalse(matcher
                        .matches(testRequest));
    }
}
