/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.statsd;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.MDC;

/**
 * Simple context listener that adds an MDC entry for the context path. Can be referenced using <code>%X{context}</code>
 * in a log4j format, like this:
 * 
 * <pre>
 * log4j.appender.CONSOLE.layout.ConversionPattern=[%d] %X{context} - [%t] %5p - %c{1}: %m%n
 * </pre>
 * 
 * @author Dave Syer
 * 
 */
public class Log4jContextInitializer implements ServletContextListener, Filter {

	@Override
	public void contextInitialized(ServletContextEvent sce) {
		MDC.put("context", sce.getServletContext().getContextPath());
	}

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		MDC.put("context", ((HttpServletRequest)request).getContextPath());
		try {
			chain.doFilter(request, response);
		} finally {
			MDC.remove("context");
		}
	}

	@Override
	public void destroy() {
	}

}
