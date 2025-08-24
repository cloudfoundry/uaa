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

import org.cloudfoundry.identity.uaa.util.EmptyEnumerationOfString;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class HttpHeadersFilterRequestWrapperTest {

    private static final List<String> BAD_HEADERS = List.of("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Prefix", "Forwarded");

    MockHttpServletRequest mock;
    private HttpHeadersFilterRequestWrapper request;

    @BeforeEach
    void setUp() {
        mock = new MockHttpServletRequest(HttpMethod.GET.name(), "http://localhost:8080/uaa/login");
        mock.addHeader("X-Forwarded-For", "proxy-ip");
        mock.addHeader("X-Forwarded-Host", "proxy-host");
        mock.addHeader("X-Forwarded-Proto", "proxy-host");
        mock.addHeader("X-Forwarded-Prefix", "/otherpath");
        mock.addHeader("Forwarded", "for=proxy-ip;host=proxy-host;for=my-proxy;by=somebody-else");
        mock.addHeader("Other-header", "other-value");
        request = new HttpHeadersFilterRequestWrapper(BAD_HEADERS, mock);
    }

    @Test
    void filter_is_case_insensitive() {
        request = new HttpHeadersFilterRequestWrapper(Collections.singletonList("x-forwarded-host"), mock);
        assertThat(request.getHeader("X-Forwarded-Host")).isNull();
        assertThat(request.getHeader("X-Forwarded-For")).isNotNull();
    }

    @Test
    void null_filter_list() {
        request = new HttpHeadersFilterRequestWrapper(null, mock);
        List<String> actual = Collections.list(request.getHeaderNames());
        List<String> wanted = new ArrayList<>(BAD_HEADERS);
        wanted.add("Other-header");
        assertThat(actual).containsExactlyInAnyOrderElementsOf(wanted);
    }

    @Test
    void filtered_available_headers() {
        request = new HttpHeadersFilterRequestWrapper(BAD_HEADERS, mock);
        List<String> actual = Collections.list(request.getHeaderNames());
        List<String> wanted = Collections.singletonList("Other-header");
        assertThat(actual).containsExactlyInAnyOrderElementsOf(wanted);
    }

    @Test
    void non_filtered_available_headers() {
        request = new HttpHeadersFilterRequestWrapper(Collections.emptyList(), mock);
        List<String> actual = Collections.list(request.getHeaderNames());
        List<String> wanted = new ArrayList<>(BAD_HEADERS);
        wanted.add("Other-header");
        assertThat(actual).containsExactlyInAnyOrderElementsOf(wanted);
    }

    @Test
    void filtered_x_forwarded_headers_single_header() {
        for (String header : BAD_HEADERS) {
            assertThat(request.getHeader(header)).as("Header %s should be filtered.".formatted(header)).isNull();
        }
    }

    @Test
    void non_filtered_x_forwarded_headers_single_header() {
        request = new HttpHeadersFilterRequestWrapper(Collections.emptyList(), mock);
        for (String header : BAD_HEADERS) {
            assertThat(request.getHeader(header)).as("Header %s should be present.".formatted(header)).isNotNull();
        }
    }

    @Test
    void filtered_x_forwarded_headers_multi_header() {
        for (String header : BAD_HEADERS) {
            assertThat(request.getHeaders(header).hasMoreElements()).as("Header %s should return empty enumeration.".formatted(header)).isFalse();
            assertThat(request.getHeaders(header)).as("Header %s should return singleton enumeration .".formatted(header)).isSameAs(EmptyEnumerationOfString.EMPTY_ENUMERATION);
        }
    }

    @Test
    void non_filtered_x_forwarded_headers_multi_header() {
        request = new HttpHeadersFilterRequestWrapper(Collections.emptyList(), mock);
        for (String header : BAD_HEADERS) {
            assertThat(request.getHeaders(header).hasMoreElements()).as("Header %s should return empty enumeration.".formatted(header)).isTrue();
            assertThat(request.getHeaders(header).nextElement()).as("Header %s should return a value.".formatted(header)).isNotNull();
        }
    }
}
