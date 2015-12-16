/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Custom request matcher which allows endpoints in the UAA to be matched as
 * substrings and also differentiation based
 * on the content type (e.g. JSON vs HTML) specified in the Accept request
 * header, thus allowing different filter chains
 * to be configured for browser and command-line clients.
 * <p>
 * Currently just looks for a match of the configured MIME-type in the accept
 * header when deciding whether to match the request. There is no parsing of
 * priorities in the header.
 */
public final class UaaRequestMatcher implements RequestMatcher, BeanNameAware {

    private static final Log logger = LogFactory.getLog(UaaRequestMatcher.class);

    private final String path;

    private List<String> accepts;

    private HttpMethod method;

    private Map<String, String> parameters = new HashMap<String, String>();

    private Map<String, List<String>> expectedHeaders = new HashMap<String, List<String>>();

    private String name;

    public UaaRequestMatcher(String path) {
        Assert.hasText(path);
        if (path.contains("*")) {
            throw new IllegalArgumentException("UaaRequestMatcher is not intended for use with wildcards");
        }
        this.path = path;
    }

    /**
     * The HttpMethod that the request should be made with. Optional (if null,
     * then all values match)
     *
     * @param method
     */
    public void setMethod(HttpMethod method) {
        this.method = method;
    }

    /**
     * A media type that should be present in the accept header for a request to
     * match. Optional (if null then all
     * values match).
     *
     * @param accepts the accept header value to set
     */
    public void setAccept(List<String> accepts) {
        this.accepts = Collections.unmodifiableList(accepts);
        setHeaders(Collections.singletonMap("accept", this.accepts));
    }

    /**
     * A map of request parameter name and values to match against. If all the
     * specified parameters are present and
     * match the values given then the accept header will be ignored.
     *
     * @param parameters the parameter matches to set
     */
    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        String message = "";
        if (logger.isDebugEnabled()) {
            message = request.getRequestURI() + "'; '" + request.getContextPath() + path + "' with parameters="
                            + parameters + " and headers " + expectedHeaders;
            logger.debug("["+name+"] Checking match of request : '" + message);
        }

        if (!request.getRequestURI().startsWith(request.getContextPath() + path)) {
            return false;
        }

        if (method != null && !method.toString().equals(request.getMethod().toUpperCase())) {
            return false;
        }

        for (Entry<String, List<String>> expectedHeaderEntry : expectedHeaders.entrySet()) {
            String requestValue = request.getHeader(expectedHeaderEntry.getKey());
            if ("accept".equalsIgnoreCase(expectedHeaderEntry.getKey())) {
                if (!matchesAcceptHeader(requestValue, expectedHeaderEntry.getValue())) {
                    return false;
                }
            }
            else if (!matchesHeader(requestValue, expectedHeaderEntry.getValue())) {
                return false;
            }
        }

        for (String key : parameters.keySet()) {
            String value = request.getParameter(key);
            if (value == null || !value.startsWith(parameters.get(key))) {
                return false;
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("["+name+"]Matched request " + message);
        }
        return true;
    }

    private boolean matchesHeader(String requestValue, List<String> expectedValues) {
        for (String headerValue : expectedValues) {
            //TODO - Spring Security Oauth2 v2 upgrade - bearer changed capitalization
            if ("bearer ".equalsIgnoreCase(headerValue)) {
                //case insensitive for Authorization: Bearer match
                if (requestValue == null || !requestValue.toLowerCase().startsWith(headerValue)) {
                    return false;
                }
            } else if (requestValue == null || !requestValue.startsWith(headerValue)) {
                return false;
            }
        }
        return true;
    }

    private boolean matchesAcceptHeader(String requestValue, List<String> expectedValues) {
        // Accept header is not required to be checked!
        if (requestValue == null) {
            return true;
        }

        List<MediaType> requestValues = MediaType.parseMediaTypes(requestValue);
        for (String expectedValue : expectedValues) {
            if (MediaType.parseMediaType(expectedValue).includes(requestValues.get(0))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof UaaRequestMatcher)) {
            return false;
        }
        UaaRequestMatcher other = (UaaRequestMatcher) obj;
        if (!this.path.equals(other.path)) {
            return false;
        }

        if (!((this.method == null && other.method == null) || (this.method != null && other.method != null && this.method == other.method))) {
            return false;
        }

        if (!((this.parameters == null && other.parameters == null) || (this.parameters != null && this.parameters
                        .equals(other.parameters)))) {
            return false;
        }

        if (!((this.accepts == null && other.accepts == null) || (this.accepts != null && this.accepts
                        .equals(other.accepts)))) {
            return false;
        }

        if (!((this.expectedHeaders == null && other.expectedHeaders == null) || (this.expectedHeaders != null && this.expectedHeaders
                        .equals(other.expectedHeaders)))) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int code = 31 ^ path.hashCode();
        if (method != null) {
            code ^= method.hashCode();
        }
        if (accepts != null) {
            code ^= accepts.hashCode();
        }
        if (parameters != null) {
            code ^= parameters.hashCode();
        }
        return code;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UAAPath("+name+") ['").append(path).append("'");

        if (accepts != null) {
            sb.append(", ").append(accepts);
        }

        sb.append("]");

        return sb.toString();
    }

    public void setHeaders(Map<String, List<String>> headers) {
        for (String headerName : headers.keySet()) {
            List<String> expectedValues = new ArrayList<String>();
            expectedValues.addAll(headers.get(headerName));
            expectedHeaders.put(headerName, expectedValues);
        }
    }

    @Override
    public void setBeanName(String name) {
        this.name=name;
    }
}
