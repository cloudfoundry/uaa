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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;
import static java.util.Optional.ofNullable;

public class HttpHeadersFilterRequestWrapper extends HttpServletRequestWrapper {
    private final List<String> filteredHeaders;

    public HttpHeadersFilterRequestWrapper(List<String> badHeaders, HttpServletRequest request) {
        super(request);
        this.filteredHeaders = unmodifiableList(ofNullable(badHeaders).orElse(emptyList()));
    }

    @Override
    public String getHeader(String name) {
        if (shouldFilter(name)) {
            return null;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (shouldFilter(name)) {
            return EmptyEnumerationOfString.EMPTY_ENUMERATION;
        }
        return super.getHeaders(name);
    }

    private boolean shouldFilter(String name) {
        return filteredHeaders.stream().anyMatch(s -> s.equalsIgnoreCase(name));
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        List<String> headerNames = Collections.list(super.getHeaderNames());
        headerNames.removeIf(this::shouldFilter);
        return Collections.enumeration(headerNames);
    }
}
