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

import org.springframework.web.context.ServletContextAware;

import javax.servlet.ServletContext;
import javax.servlet.SessionCookieConfig;

import static org.springframework.util.StringUtils.hasText;

public class UaaSessionCookieConfig implements SessionCookieConfig, ServletContextAware {

    private String comment;
    private String domain;
    private int maxAge;
    private String path;
    private boolean httpOnly;
    private String name;
    private boolean secure;



    @Override
    public void setServletContext(ServletContext servletContext) {
        SessionCookieConfig config = servletContext.getSessionCookieConfig();
        if (hasText(getComment())) {
            config.setComment(getComment());
        }
        if (hasText(getDomain())) {
            config.setDomain(getDomain());
        }
        if (getMaxAge()>Integer.MIN_VALUE) {
            config.setMaxAge(getMaxAge());
        }
        if (getPath()!=null) {
            config.setPath(getPath());
        }
        config.setHttpOnly(isHttpOnly());
        config.setSecure(isSecure());
        if (hasText(getName())) {
            config.setName(getName());
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
