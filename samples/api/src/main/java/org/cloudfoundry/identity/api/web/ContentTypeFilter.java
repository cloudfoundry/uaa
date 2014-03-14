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
package org.cloudfoundry.identity.api.web;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * A servlet filter that adds a content type header to any path that matches one
 * of a set of path patterns. Used to
 * serve static content without a filename extension with a specific media type,
 * for instance.
 * 
 * @author Dave Syer
 * 
 */
public class ContentTypeFilter implements Filter {

    private Map<String, String> mediaTypes = new HashMap<String, String>();

    /**
     * Maps the paths that should be matched to specific media types. The paths
     * should begin with a leading "/" and
     * should not include the application context path.
     * 
     * @param mediaTypes a map from path to media type
     */
    public void setMediaTypes(Map<String, String> mediaTypes) {
        this.mediaTypes = mediaTypes;
    }

    @Override
    public void destroy() {
    }

    /**
     * Add a content type header to any request whose path matches one of the
     * supplied paths.
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
                    ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        for (String path : mediaTypes.keySet()) {
            if (matches(httpServletRequest, path)) {
                response.setContentType(mediaTypes.get(path));
                break;
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig config) throws ServletException {
    }

    private boolean matches(HttpServletRequest request, String path) {
        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        if ("".equals(request.getContextPath())) {
            return uri.endsWith(path);
        }

        return uri.endsWith(request.getContextPath() + path);
    }
}
