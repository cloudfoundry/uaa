/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import javax.servlet.ServletContext;
import javax.servlet.SessionCookieConfig;
import javax.servlet.SessionTrackingMode;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.ServletContextAware;

import static org.springframework.util.StringUtils.hasText;

public class UaaSessionCookieConfig implements SessionCookieConfig, ServletContextAware {

    protected static Logger logger = LoggerFactory.getLogger(UaaSessionCookieConfig.class);

    private String comment;
    private String domain;
    private int maxAge;
    private String path;
    private boolean httpOnly;
    private String name;
    private boolean secure;



    @Override
    public void setServletContext(ServletContext servletContext) {
        logger.debug("Configuring session cookie.");

        try {
            SessionCookieConfig config = servletContext.getSessionCookieConfig();
            if (hasText(getComment())) {
                logger.debug(String.format("Configuring session cookie - Comment: %s", getComment()));
                config.setComment(getComment());
            }
            if (hasText(getDomain())) {
                logger.debug(String.format("Configuring session cookie - Domain: %s", getDomain()));
                config.setDomain(getDomain());
            }
            if (getMaxAge()>Integer.MIN_VALUE) {
                logger.debug(String.format("Configuring session cookie - MaxAge: %s", getMaxAge()));
                config.setMaxAge(getMaxAge());
            }
            if (getPath()!=null) {
                logger.debug(String.format("Configuring session cookie - Path: %s", getPath()));
                config.setPath(getPath());
            }
            logger.debug(String.format("Configuring session cookie - HttpOnly: %s", isHttpOnly()));
            config.setHttpOnly(isHttpOnly());
            logger.debug(String.format("Configuring session cookie - Secure: %s", isSecure()));
            config.setSecure(isSecure());
            if (hasText(getName())) {
                logger.debug(String.format("Configuring session cookie - Name: %s", getName()));
                config.setName(getName());
            }
            HashSet<SessionTrackingMode> trackingModes = new HashSet<>();
            trackingModes.add(SessionTrackingMode.COOKIE);
            servletContext.setSessionTrackingModes(trackingModes);
        } catch (Exception e) {
            logger.error("Ignoring session cookie config - unable to configure UAA session cookie", e);
        }
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public boolean isSecure() {
        return secure;
    }

    @Override
    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getDomain() {
        return domain;
    }

    @Override
    public void setDomain(String domain) {
        this.domain = domain;
    }

    @Override
    public boolean isHttpOnly() {
        return httpOnly;
    }

    @Override
    public void setHttpOnly(boolean httpOnly) {
        this.httpOnly = httpOnly;
    }

    @Override
    public int getMaxAge() {
        return maxAge;
    }

    @Override
    public void setMaxAge(int maxAge) {
        this.maxAge = maxAge;
    }

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public void setPath(String path) {
        this.path = path;
    }
}
