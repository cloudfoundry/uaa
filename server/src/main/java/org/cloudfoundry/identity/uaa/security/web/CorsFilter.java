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

import org.cloudfoundry.identity.uaa.zone.CorsConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.containsIgnoreCase;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.ACCEPT_LANGUAGE;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_MAX_AGE;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_LANGUAGE;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.ORIGIN;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.http.HttpMethod.PATCH;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.METHOD_NOT_ALLOWED;

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

    static final Logger logger = LoggerFactory.getLogger(CorsFilter.class);
    public static final String X_REQUESTED_WITH = "X-Requested-With";
    public static final String WILDCARD = "*";

    private CorsConfiguration xhrConfiguration = new CorsConfiguration();
    private CorsConfiguration defaultConfiguration = new CorsConfiguration();

    public CorsFilter() {
        //configure defaults for XHR vs non-XHR requests
        xhrConfiguration.setAllowedMethods(Arrays.asList(GET.toString(), OPTIONS.toString()));
        defaultConfiguration.setAllowedMethods(Arrays.asList(GET.toString(), OPTIONS.toString(), POST.toString(), PUT.toString(), DELETE.toString(), PATCH.toString()));

        xhrConfiguration.setAllowedHeaders(Arrays.asList(ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, CONTENT_LANGUAGE,AUTHORIZATION, X_REQUESTED_WITH));
        defaultConfiguration.setAllowedHeaders(Arrays.asList(ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, CONTENT_LANGUAGE,AUTHORIZATION));

        xhrConfiguration.setAllowedCredentials(true);
        defaultConfiguration.setAllowedCredentials(false);
    }

    @PostConstruct
    public void initialize() {
        for (CorsConfiguration configuration : Arrays.asList(xhrConfiguration, defaultConfiguration)) {
            String type = (configuration == xhrConfiguration ? "xhr" : "default");
            configuration.getAllowedUriPatterns().clear();
            configuration.getAllowedOriginPatterns().clear();
            if (configuration.getAllowedUris() != null) {
                for (String allowedUri : configuration.getAllowedUris()) {
                    try {
                        configuration.getAllowedUriPatterns().add(Pattern.compile(allowedUri));
                        logger.debug(String.format("URI '%s' is allowed for a %s CORS requests.", allowedUri, type));
                    } catch (PatternSyntaxException patternSyntaxException) {
                        logger.error("Invalid regular expression pattern in cors."+type+".allowed.uris: " + allowedUri, patternSyntaxException);
                    }
                }
            }
            if (configuration.getAllowedOrigins() != null) {
                for (String allowedOrigin : configuration.getAllowedOrigins()) {
                    try {
                        configuration.getAllowedOriginPatterns().add(Pattern.compile(allowedOrigin));
                        logger.debug(String.format("Origin '%s' is allowed for a %s CORS requests.", allowedOrigin, type));
                    } catch (PatternSyntaxException patternSyntaxException) {
                        logger.error("Invalid regular expression pattern in cors."+type+".allowed.origins: " + allowedOrigin, patternSyntaxException);
                    }
                }
            }
        }
    }


    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain filterChain) throws ServletException, IOException {

        if (!isCrossOriginRequest(request)) {
            //if the Origin header is not present.
            //Process as usual
            filterChain.doFilter(request, response);
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("CORS Processing request: "+getRequestInfo(request));
        }
        if (isXhrRequest(request)) {
            handleRequest(request, response, filterChain, getXhrConfiguration());
        } else {
            handleRequest(request, response, filterChain, getDefaultConfiguration());
        }
        if (logger.isDebugEnabled()) {
            logger.debug("CORS processing completed for: "+getRequestInfo(request)+" Status:"+response.getStatus());
        }
    }

    protected boolean handleRequest(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain,
                                    CorsConfiguration configuration) throws IOException, ServletException {

        boolean isPreflightRequest = OPTIONS.matches(request.getMethod());

        //Validate if this CORS request is allowed for this method
        String method = request.getMethod();
        if (!isPreflightRequest && !isAllowedMethod(method, configuration)) {
            logger.debug(String.format("Request with invalid method was rejected: %s", method));
            response.sendError(METHOD_NOT_ALLOWED.value(), "Illegal method.");
            return true;
        }


        // Validate the origin so we don't reflect back any potentially dangerous content.
        String origin = request.getHeader(ORIGIN);
        // While origin can be a comma delimited list, we don't allow it for CORS
        URI originURI;
        try {
            originURI = new URI(origin);
        } catch(URISyntaxException e) {
            logger.debug(String.format("Request with invalid origin was rejected: %s", origin));
            response.sendError(FORBIDDEN.value(), "Invalid origin");
            return true;
        }

        if (!isAllowedOrigin(origin, configuration)) {
            logger.debug(String.format("Request with origin: %s was rejected because it didn't match allowed origins", origin));
            response.sendError(FORBIDDEN.value(), "Illegal origin");
            return true;
        }

        String requestUri = request.getRequestURI();
        if (!isAllowedRequestUri(requestUri, configuration)) {
            logger.debug(String.format("Request with URI: %s was rejected because it didn't match allowed URIs", requestUri));
            response.sendError(FORBIDDEN.value(), "Illegal request URI");
            return true;
        }

        if (configuration.isAllowedCredentials()) {
            //if we allow credentials, send back the actual origin
            response.addHeader(ACCESS_CONTROL_ALLOW_ORIGIN, originURI.toString());
        } else {
            //send back a wildcard, this will prevent credentials
            response.addHeader(ACCESS_CONTROL_ALLOW_ORIGIN, WILDCARD);
        }

        if (isPreflightRequest) {
            logger.debug("Request is a pre-flight request");
            buildCorsPreFlightResponse(request, response, configuration);
        } else {
            logger.debug("Request cross origin request has passed validation.");
            filterChain.doFilter(request, response);
        }

        return false;
    }

    /**
     * Returns true if we believe this is an XHR request
     * We look for the presence of the X-Requested-With header
     * or that the X-Requested-With header is listed as a value
     * in the Access-Control-Request-Headers header.
     * @param request the HTTP servlet request
     * @return true if we believe this is an XHR request
     */
    protected boolean isXhrRequest(final HttpServletRequest request) {
        if (StringUtils.hasText(request.getHeader(X_REQUESTED_WITH))) {
            //the X-Requested-With header is present. This is a XHR request
            return true;
        }
        String accessControlRequestHeaders = request.getHeader(ACCESS_CONTROL_REQUEST_HEADERS);
        //One of the requested headers is X-Requested-With so we treat is as XHR request
        return StringUtils.hasText(accessControlRequestHeaders) && containsHeader(accessControlRequestHeaders, X_REQUESTED_WITH);

    }

    /**
     * Returns true if the `Origin` header is present and has any value
     * @param request the HTTP servlet request
     * @return true if the `Origin` header is present
     */
    protected boolean isCrossOriginRequest(final HttpServletRequest request) {
        //presence of the origin header indicates CORS request
        return StringUtils.hasText(request.getHeader(ORIGIN));
    }

    protected String buildCommaDelimitedString(List<String> list) {
        StringBuilder builder = new StringBuilder();
        for (String s : list) {
            if (builder.length()>0) {
                builder.append(", ");
            }
            builder.append(s);
        }
        return builder.toString();
    }

    protected List<String> splitCommaDelimitedString(String s) {
        String[] list = s.replace(" ", "").split(",");
        if (list==null || list.length==0) {
            return Collections.EMPTY_LIST;
        }
        return Arrays.asList(list);
    }

    protected void buildCorsPreFlightResponse(final HttpServletRequest request,
                                              final HttpServletResponse response,
                                              final CorsConfiguration configuration) throws IOException {
        String accessControlRequestMethod = request.getHeader(ACCESS_CONTROL_REQUEST_METHOD);

        //preflight requires the Access-Control-Request-Method header
        if (null == accessControlRequestMethod) {
            response.sendError(BAD_REQUEST.value(), "Access-Control-Request-Method header is missing");
            return;
        }

        if (!isAllowedMethod(accessControlRequestMethod, configuration)) {
            response.sendError(METHOD_NOT_ALLOWED.value(), "Illegal method requested");
            return;
        }

        //add all methods that we allow
        response.addHeader(ACCESS_CONTROL_ALLOW_METHODS, buildCommaDelimitedString(configuration.getAllowedMethods()));

        //we require Access-Control-Request-Headers header
        String accessControlRequestHeaders = request.getHeader(ACCESS_CONTROL_REQUEST_HEADERS);
        if (null == accessControlRequestHeaders) {
            response.sendError(BAD_REQUEST.value(),"Missing "+ACCESS_CONTROL_REQUEST_HEADERS+" header.");
            return;
        }
        if (!headersAllowed(accessControlRequestHeaders, configuration)) {
            response.sendError(FORBIDDEN.value(), "Illegal header requested");
            return;
        }

        //echo back what the client requested
        response.addHeader(ACCESS_CONTROL_ALLOW_HEADERS, accessControlRequestHeaders);
        //send back our configuration value
        response.addHeader(ACCESS_CONTROL_MAX_AGE, String.valueOf(configuration.getMaxAge()));
    }

    protected boolean containsHeader(final String accessControlRequestHeaders, final String header) {
        List<String> headers = splitCommaDelimitedString(accessControlRequestHeaders);
        return containsIgnoreCase(headers, header);
    }

    protected boolean headersAllowed(final String accessControlRequestHeaders, CorsConfiguration configuration) {
        List<String> headers = splitCommaDelimitedString(accessControlRequestHeaders);
        for (String header : headers) {
            if (!containsIgnoreCase(configuration.getAllowedHeaders(), header)) {
                return false;
            }
        }
        return true;
    }

    protected boolean isAllowedMethod(final String method, CorsConfiguration configuration) {
        return containsIgnoreCase(configuration.getAllowedMethods(), method);
    }

    protected boolean isAllowedRequestUri(final String uri, CorsConfiguration configuration) {
        if (StringUtils.isEmpty(uri)) {
            return false;
        }

        for (Pattern pattern : configuration.getAllowedUriPatterns()) {
            // Making sure that the pattern matches
            if (pattern.matcher(uri).find()) {
                return true;
            }
        }
        logger.debug(String.format("The '%s' URI does not allow CORS requests.", uri));
        return false;
    }

    protected boolean isAllowedOrigin(final String origin, CorsConfiguration configuration) {
        for (Pattern pattern : configuration.getAllowedOriginPatterns()) {
            // Making sure that the pattern matches
            if (pattern.matcher(origin).find()) {
                return true;
            }
        }
        logger.debug(String.format("The '%s' origin is not allowed to make CORS requests.",origin));
        return false;
    }
    //----------------REQUEST INFO ----------------------------------------------//
    public String getRequestInfo(HttpServletRequest request) {
        return String.format("URI: %s; Scheme: %s; Host: %s; Port: %s; Origin: %s; Method: %s",
                             request.getRequestURI(),
                             request.getScheme(),
                             request.getServerName(),
                             request.getServerPort(),
                             request.getHeader("Origin"),
                             request.getMethod());
    }

    //----------------CORS XHR ONLY ---------------------------------------------//
    public void setCorsXhrAllowedUris(List<String> corsXhrAllowedUris) {
        this.xhrConfiguration.setAllowedUris(corsXhrAllowedUris);
    }

    public void setCorsXhrAllowedOrigins(List<String> corsXhrAllowedOrigins) {
        this.xhrConfiguration.setAllowedOrigins(corsXhrAllowedOrigins);
    }

    public void setCorsXhrAllowedHeaders(List<String> allowedHeaders) {
        this.xhrConfiguration.setAllowedHeaders(new ArrayList(allowedHeaders));
    }

    public void setCorsXhrAllowedCredentials(boolean allowedCredentials) {
        this.xhrConfiguration.setAllowedCredentials(allowedCredentials);
    }

    public void setCorsXhrAllowedMethods(List<String> corsXhrAllowedMethods) {
        this.xhrConfiguration.setAllowedMethods(new ArrayList(corsXhrAllowedMethods));
    }

    public void setCorsXhrMaxAge(int age) {
        this.xhrConfiguration.setMaxAge(age);
    }


    //----------------CORS NON XHR ONLY ---------------------------------------------//
    public void setCorsAllowedUris(List<String> corsAllowedUris) {
        this.defaultConfiguration.setAllowedUris(corsAllowedUris);
    }

    public void setCorsAllowedOrigins(List<String> corsAllowedOrigins) {
        this.defaultConfiguration.setAllowedOrigins(corsAllowedOrigins);
    }

    public void setCorsAllowedHeaders(List<String> allowedHeaders) {
        this.defaultConfiguration.setAllowedHeaders(new ArrayList(allowedHeaders));
    }

    public void setCorsAllowedCredentials(boolean allowedCredentials) {
        this.defaultConfiguration.setAllowedCredentials(allowedCredentials);
    }

    public void setCorsAllowedMethods(List<String> corsXhrAllowedMethods) {
        this.defaultConfiguration.setAllowedMethods(new ArrayList(corsXhrAllowedMethods));
    }

    public void setCorsMaxAge(int age) {
        this.defaultConfiguration.setMaxAge(age);
    }

    //----------------CONFIGURATION GETTERS ---------------------------------------------//

    public CorsConfiguration getDefaultConfiguration() {
        return defaultConfiguration;
    }

    public CorsConfiguration getXhrConfiguration() {
        return xhrConfiguration;
    }
}