/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009, 2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 *
 * Modern browser include the X-Requested-With header when making calls through
 * the XMLHttpRequest API which allows the server CORS filtering to mitigate
 * against CSRF attacks performed by XHR requests. However, in some situations
 * XHR requests are useful. For example, when a single page JavaScript apps that
 * implements login using implicit grant wants to: 1) log the user out by
 * calling the /logout.do URI 2) get user information by calling the /userinfo
 * URI.
 *
 * To enable the scenarios described above, this filter allows CORS requests to
 * include the "X-Requested-With" header for a whitelist of URIs and origins and
 * only for the HTTP GET method.
 *
 * The implementation is based on guidance from:
 * http://www.w3.org/TR/cors/
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
 *
 */
public class CorsFilter extends OncePerRequestFilter {

    static final Log LOG = LogFactory.getLog(CorsFilter.class);

    /**
     * A comma delimited list of regular expression patterns that defines which
     * UAA URIs allow the "X-Requested-With" header in CORS requests.
     */
    @Value("#{'${cors.xhr.allowed.uris:^$}'.split(',')}")
    private List<String> corsXhrAllowedUris;

    private final List<Pattern> corsXhrAllowedUriPatterns = new ArrayList<>();

    /**
     * A comma delimited list of regular expression patterns that define which
     * origins are allowed to use the "X-Requested-With" header in CORS
     * requests.
     */
    @Value("#{'${cors.xhr.allowed.origins:^$}'.split(',')}")
    private List<String> corsXhrAllowedOrigins;

    private final List<Pattern> corsXhrAllowedOriginPatterns = new ArrayList<>();

    @Value("#{'${cors.xhr.allowed.headers:Accept,Authorization}'.split(',')}")
    private List<String> allowedHeaders;

    @PostConstruct
    public void initialize() {

        if (corsXhrAllowedUris!=null) {
            for (String allowedUri : this.corsXhrAllowedUris) {
                try {
                    this.corsXhrAllowedUriPatterns.add(Pattern.compile(allowedUri));

                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String
                            .format("URI '%s' allows 'X-Requested-With' header in CORS requests.", allowedUri));
                    }
                } catch (PatternSyntaxException patternSyntaxException) {
                    LOG.error("Invalid regular expression pattern in cors.xhr.allowed.uris: " + allowedUri);
                }
            }
        }

        if (corsXhrAllowedOrigins!=null) {
            for (String allowedOrigin : this.corsXhrAllowedOrigins) {
                try {
                    this.corsXhrAllowedOriginPatterns.add(Pattern.compile(allowedOrigin));

                    if (LOG.isDebugEnabled()) {
                        LOG.debug(String.format("Origin '%s' allowed 'X-Requested-With' header in CORS requests.",
                            allowedOrigin));
                    }
                } catch (PatternSyntaxException patternSyntaxException) {
                    LOG.error("Invalid regular expression pattern in cors.xhr.allowed.origins: " + allowedOrigin);
                }
            }
        }
    }


    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain filterChain) throws ServletException, IOException {

        if (!isCrossOriginRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (isXhrRequest(request)) {
            String method = request.getMethod();
            if (!isCorsXhrAllowedMethod(method)) {
                response.setStatus(HttpStatus.METHOD_NOT_ALLOWED.value());
                return;
            }
            String origin = request.getHeader(HttpHeaders.ORIGIN);
            String requestUri = request.getRequestURI();
            if (!isCorsXhrAllowedRequestUri(requestUri) || !isCorsXhrAllowedOrigin(origin)) {
                response.setStatus(HttpStatus.FORBIDDEN.value());
                return;
            }
            response.addHeader("Access-Control-Allow-Origin", origin);
            if ("OPTIONS".equals(request.getMethod())) {
                buildCorsXhrPreFlightResponse(request, response);
            } else {
                filterChain.doFilter(request, response);
            }
            return;
        }

        response.addHeader("Access-Control-Allow-Origin", "*");
        if (request.getHeader("Access-Control-Request-Method") != null && "OPTIONS".equals(request.getMethod())) {
            // CORS "pre-flight" request
            response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
            response.addHeader("Access-Control-Allow-Headers", "Authorization");
            response.addHeader("Access-Control-Max-Age", "1728000");
        } else {
            filterChain.doFilter(request, response);
        }
    }

    static boolean isXhrRequest(final HttpServletRequest request) {
        String xRequestedWith = request.getHeader("X-Requested-With");
        String accessControlRequestHeaders = request.getHeader("Access-Control-Request-Headers");
        return StringUtils.hasText(xRequestedWith)
                || (StringUtils.hasText(accessControlRequestHeaders) && containsHeader(
                        accessControlRequestHeaders, "X-Requested-With"));
    }

    private boolean isCrossOriginRequest(final HttpServletRequest request) {
        if (StringUtils.isEmpty(request.getHeader(HttpHeaders.ORIGIN))) {
            return false;
        }
        else {
            return true;
        }
    }

    void buildCorsXhrPreFlightResponse(final HttpServletRequest request, final HttpServletResponse response) {
        String accessControlRequestMethod = request.getHeader("Access-Control-Request-Method");
        if (null == accessControlRequestMethod) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }
        if (!"GET".equalsIgnoreCase(accessControlRequestMethod)) {
            response.setStatus(HttpStatus.METHOD_NOT_ALLOWED.value());
            return;
        }
        response.addHeader("Access-Control-Allow-Methods", "GET");

        String accessControlRequestHeaders = request.getHeader("Access-Control-Request-Headers");
        if (null == accessControlRequestHeaders) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }
        if (!headersAllowed(accessControlRequestHeaders)) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }
        response.addHeader("Access-Control-Allow-Headers", "Authorization, X-Requested-With");
        response.addHeader("Access-Control-Max-Age", "1728000");
    }

    private static boolean containsHeader(final String accessControlRequestHeaders, final String header) {
        List<String> headers = Arrays.asList(accessControlRequestHeaders.replace(" ", "").toLowerCase().split(","));
        return headers.contains(header.toLowerCase());
    }

    private boolean headersAllowed(final String accessControlRequestHeaders) {
        List<String> headers = Arrays.asList(accessControlRequestHeaders.replace(" ", "").split(","));
        for (String header : headers) {
            if (!"X-Requested-With".equalsIgnoreCase(header) && !this.allowedHeaders.contains(header)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isCorsXhrAllowedMethod(final String method) {
        if ("GET".equalsIgnoreCase(method) || "OPTIONS".equalsIgnoreCase(method)) {
            return true;
        }
        return false;
    }

    private boolean isCorsXhrAllowedRequestUri(final String uri) {
        if (StringUtils.isEmpty(uri)) {
            return false;
        }

        for (Pattern pattern : this.corsXhrAllowedUriPatterns) {
            // Making sure that the pattern matches
            if (pattern.matcher(uri).find()) {
                return true;
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("The '%s' URI does not allow CORS requests with the 'X-Requested-With' header.",
                    uri));
        }
        return false;
    }

    private boolean isCorsXhrAllowedOrigin(final String origin) {
        for (Pattern pattern : this.corsXhrAllowedOriginPatterns) {
            // Making sure that the pattern matches
            if (pattern.matcher(origin).find()) {
                return true;
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format(
                    "The '%s' origin is not allowed to make CORS requests with the 'X-Requested-With' header.",
                    origin));
        }
        return false;
    }

    public void setCorsXhrAllowedUris(List<String> corsXhrAllowedUris) {
        this.corsXhrAllowedUris = corsXhrAllowedUris;
    }

    public void setCorsXhrAllowedOrigins(List<String> corsXhrAllowedOrigins) {
        this.corsXhrAllowedOrigins = corsXhrAllowedOrigins;
    }

    public void setAllowedHeaders(List<String> allowedHeaders) {
        this.allowedHeaders = allowedHeaders;
    }
}