/*
 * *****************************************************************************
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

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * This filter ensures that the {@link HttpServletRequest#getScheme()} and {@link HttpServletRequest#getLocalPort()}
 * return the correct values (https & 443) when the client made an HTTPS request. This is necessary because traffic
 * received by the UAA is usually coming from the CF gorouter, which terminates TLS and plain HTTP to talk to the UAA.
 * Therefore, the Tomcat server hosting UAA sees {@code scheme=http} and {@code port=80}. This filter corrects this.
 * <p>
 * This is necessary in the login-ui part of the application, notably because we build {@code redirect_uri}s for
 * OAuth2 and OIDC based on the base URL of the request, with {@link UaaUrlUtils#getBaseURL(HttpServletRequest)}.
 * Without this filter, a user visiting {@code https://uaa.example.com/uaa/login} would have an authorization
 * request with an upstream provider be {@code ...&redirect_uri=http://uaa.example.com/uaa/login} (notice http://).
 */
public class HttpsHeaderFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(HttpsHeaderFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        FixHttpsSchemeRequest modifiedRequest = new FixHttpsSchemeRequest((HttpServletRequest) request);
        chain.doFilter(modifiedRequest, response);
    }

    @Override
    public void init(FilterConfig arg0) {
        logger.info("Filter inited");
    }

    @Override
    public void destroy() {
    }

}
