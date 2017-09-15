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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static java.util.stream.Collectors.toList;
import static javax.servlet.http.HttpServletResponse.SC_SERVICE_UNAVAILABLE;

public class DegradedModeUaaFilter extends OncePerRequestFilter {

    private static Log logger = LogFactory.getLog(DegradedModeUaaFilter.class);

    private Set<String> permittedEndpoints = emptySet();
    private Set<String> permittedMethods = emptySet();
    private List<AntPathRequestMatcher> endpoints = emptyList();
    private boolean enabled = false;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (isEnabled()) {
            if ( isMethodAllowed(request) || isEndpointAllowed(request)) {
                filterChain.doFilter(request, response);
            } else {
                logger.debug(format("Operation Not permitted in degraded mode for URL:%s and method:%s",
                                    request.getRequestURI(),
                                    request.getMethod()
                             )
                );
                Map<String, String> json = getErrorData();
                if (acceptsJson(request)) {
                    response.setStatus(SC_SERVICE_UNAVAILABLE);
                    response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write(JsonUtils.writeValueAsString(json));
                    response.getWriter().flush();
                    response.getWriter().close();
                } else {
                    response.sendError(SC_SERVICE_UNAVAILABLE, json.get("description"));
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }

    protected Map<String, String> getErrorData() {
        String error = "uaa_unavailable";
        String description  = "UAA intentionally in degraded mode, operation not permitted. Please try later.";
        Map<String, String> json = new HashMap<>();
        json.put("error", error);
        json.put("error_description", description);
        return json;
    }

    protected boolean acceptsJson(HttpServletRequest request) {
        List<MediaType> mediaTypes = MediaType.parseMediaTypes(request.getHeader(HttpHeaders.ACCEPT));
        return mediaTypes.stream().anyMatch(m -> m.isCompatibleWith(MediaType.APPLICATION_JSON));
    }

    protected boolean isMethodAllowed(HttpServletRequest request) {
        return getPermittedMethods().contains(request.getMethod().toUpperCase());
    }

    public boolean isEndpointAllowed(HttpServletRequest request) {
        return endpoints.stream().anyMatch(m -> m.matches(request));
    }

    public void setPermittedEndpoints(Set<String> permittedEndpoints) {
        this.permittedEndpoints = permittedEndpoints;
        if (permittedEndpoints==null) {
            this.endpoints = emptyList();
        } else {
            this.endpoints =
                permittedEndpoints
                    .stream()
                    .map(s -> new AntPathRequestMatcher(s))
                    .collect(toList());
        }
    }


    public Set<String> getPermittedEndpoints() {
        return permittedEndpoints;
    }

    public Set<String> getPermittedMethods() {
        return permittedMethods;
    }

    public void setPermittedMethods(Set<String> permittedMethods) {
        this.permittedMethods = ofNullable(permittedMethods).orElse(emptySet());
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
