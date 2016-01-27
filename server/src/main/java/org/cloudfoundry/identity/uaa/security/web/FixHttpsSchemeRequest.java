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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FixHttpsSchemeRequest extends HttpServletRequestWrapper {

    private static final Logger logger = LoggerFactory.getLogger(FixHttpsSchemeRequest.class);

    @Override
    public String getScheme() {
        String scheme = super.getScheme();
        logger.debug("Request X-Forwarded-Proto " + super.getHeader("X-Forwarded-Proto"));

        if ("http".equals(scheme) &&
                        "https".equals(super.getHeader("X-Forwarded-Proto"))) {
            scheme = "https";
        }
        return scheme;
    }

    @Override
    public int getServerPort() {
        int port = super.getServerPort();
        String scheme = super.getScheme();
        if ("http".equals(scheme) &&
                        "https".equals(super.getHeader("X-Forwarded-Proto"))) {
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
        if ((scheme.equals("http") && (port != 80))
                        || (scheme.equals("https") && (port != 443))) {
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
