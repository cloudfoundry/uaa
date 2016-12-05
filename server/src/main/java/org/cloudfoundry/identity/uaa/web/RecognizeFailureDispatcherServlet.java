/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.DispatcherServlet;

import javax.servlet.GenericServlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

public class RecognizeFailureDispatcherServlet extends GenericServlet {

    private static Log logger = LogFactory.getLog(RecognizeFailureDispatcherServlet.class);
    protected static final String HEADER = "X-Cf-Uaa-Error";
    protected static final String HEADER_MSG = "Server failed to start. Possible configuration error.";

    private volatile boolean failed = false;
    private DispatcherServlet delegate = new DispatcherServlet();

    public void setDelegate(DispatcherServlet delegate) {
        this.delegate = delegate;
    }

    public RecognizeFailureDispatcherServlet() {
        super();
    }


    @Override
    public void init(ServletConfig config) throws ServletException {
        try {
            delegate.init(config);
        } catch (Exception e) {
            logger.fatal("Unable to start UAA application.", e);
            failed = true;
        }
    }

    @Override
    public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
        if (failed) {
            String msg = "FAILURE";
            HttpServletResponse response = (HttpServletResponse) res;
            response.addHeader(HEADER, HEADER_MSG);
            response.setContentType(MediaType.TEXT_PLAIN_VALUE);
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.getWriter().write(msg);
            response.getWriter().flush();
        } else {
            delegate.service(req,res);
        }
    }

    @Override
    public void destroy() {
        delegate.destroy();
    }

    public void setEnvironment(Environment environment) {
        delegate.setEnvironment(environment);
    }

    public ConfigurableEnvironment getEnvironment() {
        return delegate.getEnvironment();
    }


    @Override
    public String getInitParameter(String name) {
        return delegate.getInitParameter(name);
    }

    @Override
    public Enumeration<String> getInitParameterNames() {
        return delegate.getInitParameterNames();
    }

    @Override
    public ServletConfig getServletConfig() {
        return delegate.getServletConfig();
    }

    @Override
    public ServletContext getServletContext() {
        return delegate.getServletContext();
    }

    @Override
    public String getServletInfo() {
        return delegate.getServletInfo();
    }

    @Override
    public void init() throws ServletException {
        delegate.init();
    }

    @Override
    public void log(String msg) {
        delegate.log(msg);
    }

    @Override
    public void log(String message, Throwable t) {
        delegate.log(message, t);
    }

    @Override
    public String getServletName() {
        return delegate.getServletName();
    }
}
