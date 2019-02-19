/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.security.oauth2.common.util.OAuth2Utils.RESPONSE_TYPE;

public class DisableIdTokenResponseTypeFilter extends OncePerRequestFilter {

    public static final String ID_TOKEN = "id_token";

    protected static Log logger = LogFactory.getLog(DisableIdTokenResponseTypeFilter.class);

    private boolean active;
    private final List<String> paths;

    public DisableIdTokenResponseTypeFilter(boolean active, List<String> paths) {
        this.paths = paths;
        this.active = active;
    }

    public boolean isIdTokenDisabled() {
        return active;
    }

    public void setIdTokenDisabled(boolean disabled) {
        this.active = disabled;
    }

    protected boolean applyPath(String path) {
        if (paths==null || paths.size()==0 || path == null) {
            return false;
        }
        AntPathMatcher matcher = new AntPathMatcher();
        for (String pattern : paths) {
            if (matcher.isPattern(pattern)) {
                if (matcher.match(pattern, path)) {
                    return true;
                }
            } else { //exact match
                if (pattern.equals(path)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.debug("Processing id_token disable filter");

        HttpServletRequest requestWrapper = request;
        logger.debug(String.format("pre id_token disable:%s pathinfo:%s request_uri:%s response_type:%s",isIdTokenDisabled(), requestWrapper.getPathInfo(), request.getRequestURI() ,requestWrapper.getParameter(RESPONSE_TYPE)));
        if (isIdTokenDisabled() && (applyPath(request.getPathInfo()) || applyPath(request.getRequestURI()))) {
            requestWrapper = new RemoveIdTokenParameterValueWrapper(request);
        }
        logger.debug(String.format("post id_token disable:%s pathinfo:%s request_uri:%s response_type:%s",isIdTokenDisabled(), requestWrapper.getPathInfo(), request.getRequestURI() ,requestWrapper.getParameter(RESPONSE_TYPE)));
        filterChain.doFilter(requestWrapper, response);
    }

    public class RemoveIdTokenParameterValueWrapper extends HttpServletRequestWrapper {

        public RemoveIdTokenParameterValueWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getParameter(String name) {
            if (RESPONSE_TYPE.equals(name)) {
                return removeIdTokenValue(super.getParameter(name));
            } else {
                return super.getParameter(name);
            }
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> map = super.getParameterMap();
            if (map.containsKey(RESPONSE_TYPE)) {
                HashMap<String, String[]> result = new HashMap<>(map);
                result.put(RESPONSE_TYPE, getParameterValues(RESPONSE_TYPE));
                map = result;
            }
            return map;
        }

        @Override
        public String[] getParameterValues(String name) {
            String[] values = super.getParameterValues(name);
            if (RESPONSE_TYPE.equals(name)) {
                for (int i=0; values!=null && i<values.length; i++) {
                    values[i] = removeIdTokenValue(values[i]);
                }
            }
            return values;
        }


        private String removeIdTokenValue(String value) {
            if (StringUtils.hasText(value) && value.contains(ID_TOKEN)) {
                return value.replace(ID_TOKEN, "").trim();
            } else {
                return value;
            }
        }
    }
}
