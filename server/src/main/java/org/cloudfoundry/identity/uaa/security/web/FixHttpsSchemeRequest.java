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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FixHttpsSchemeRequest extends HttpServletRequestWrapper {

    private static final Logger logger = LoggerFactory.getLogger(FixHttpsSchemeRequest.class);
    private static final String HTTPS = "https";
    private static final String HTTP = "http";

    @Override
    public String getScheme() {
        String scheme = super.getScheme();
        String xForwardedProto = super.getHeader("X-Forwarded-Proto");
        logger.debug("Request X-Forwarded-Proto {}", xForwardedProto);

        if (HTTP.equals(scheme) &&
                HTTPS.equals(xForwardedProto)) {
            scheme = HTTPS;
        }
        return scheme;
    }

    @Override
    public int getServerPort() {
        int port = super.getServerPort();
        String scheme = super.getScheme();
        if (HTTP.equals(scheme) &&
                HTTPS.equals(super.getHeader("X-Forwarded-Proto"))) {
            port = 443;
        }
        return port;
    }

    @Override
    public StringBuffer getRequestURL() {
        StringBuffer url = new StringBuffer();
        String scheme = getScheme();
        int port = getServerPort();
        if (port < 0) {
            port = 80;
        }

        url.append(scheme);
        url.append("://");
        url.append(getServerName());
        if ((HTTP.equals(scheme) && (port != 80))
                || (HTTPS.equals(scheme) && (port != 443))) {
            url.append(':');
            url.append(port);
        }
        url.append(getRequestURI());

        return url;
    }

    public FixHttpsSchemeRequest(HttpServletRequest request) {
        super(request);
    }
}
