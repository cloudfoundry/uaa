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

package org.cloudfoundry.identity.uaa.security.web;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.http.MediaType;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.util.Assert;

/**
 * Post processor which injects an additional filter at the head
 * of each security filter chain.
 *
 * If the requireHttps property is set, and a non HTTP request is received (as determined by the absence of the
 * <tt>httpsHeader</tt>) the filter will either redirect with a 301 or send an error code to the client.
 * Filter chains for which a redirect is required should be added to the <tt>redirectToHttps</tt> list (typically
 * those serving browser clients). Clients in this list will also receive an HSTS response header, as defined in
 * http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-14.
 *
 * HTTP requests from any other clients will receive a JSON error message.
 *
 * The filter also wraps calls to the <tt>getRemoteAddr</tt> to give a more accurate value for the remote client IP,
 * making use of the <tt>clientAddrHeader</tt> if available in the request.
 *
 *
 * @author Luke Taylor
 */
@ManagedResource
public class SecurityFilterChainPostProcessor implements BeanPostProcessor {
	private final Log logger = LogFactory.getLog(getClass());
	private boolean requireHttps = false;
	private List<String> redirectToHttps = Collections.emptyList();
	private List<String> ignore = Collections.emptyList();
	private boolean dumpRequests = false;

	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		if (bean instanceof SecurityFilterChain && !ignore.contains(beanName)) {
			logger.info("Processing security filter chain " + beanName);

			SecurityFilterChain fc = (SecurityFilterChain)bean;

			Filter uaaFilter;

			if (requireHttps) {
				uaaFilter = new HttpsEnforcementFilter(beanName, redirectToHttps.contains(beanName));
			} else {
				uaaFilter = new UaaLoggingFilter(beanName);
			}
			fc.getFilters().add(0, uaaFilter);
		}

		return bean;
	}

	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	/**
	 * If set to true, HTTPS will be required for all requests.
	 */
	public void setRequireHttps(boolean requireHttps) {
		this.requireHttps = requireHttps;
	}

	/**
	 * Debugging feature. If enabled, and debug logging is enabled
	 */
	@ManagedAttribute(description = "Enable dumping of incoming requests to the debug log")
	public void setDumpRequests(boolean dumpRequests) {
		this.dumpRequests = dumpRequests;
	}

	public void setRedirectToHttps(List<String> redirectToHttps) {
		Assert.notNull(redirectToHttps);
		this.redirectToHttps = redirectToHttps;
	}

	/**
	 * List of filter chains which should be ignored completely.
	 */
	public void setIgnore(List<String> ignore) {
		Assert.notNull(ignore);
		this.ignore = ignore;
	}

	final class HttpsEnforcementFilter extends UaaLoggingFilter {
		private final int httpsPort = 443;
		private final boolean redirect;

		HttpsEnforcementFilter(String name, boolean redirect) {
			super(name);
			this.redirect = redirect;
		}

		public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
			HttpServletRequest request = (HttpServletRequest) req;
			HttpServletResponse response = (HttpServletResponse) res;

			if (request.isSecure()) {
				// Ok. Just pass on.
				if (redirect) {
					// Set HSTS header for browser clients
					response.setHeader("Strict-Transport-Security", "max-age=31536000");
				}
				super.doFilter(req, response, chain);
				return;
			}

			logger.debug("Bad (non-https) request received from: " + request.getRemoteHost());

			if (dumpRequests) {
				logger.debug(dumpRequest(request));
			}

			if (redirect) {
				RedirectUrlBuilder rb = new RedirectUrlBuilder();
				rb.setScheme("https");
				rb.setPort(httpsPort);
				rb.setContextPath(request.getContextPath());
				rb.setServletPath(request.getServletPath());
				rb.setPathInfo(request.getPathInfo());
				rb.setQuery(request.getQueryString());
				rb.setServerName(request.getServerName());
				// Send a 301 as suggested by
				// http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-14#section-7.2
				String url = rb.getUrl();
				if (logger.isDebugEnabled()) {
					logger.debug("Redirecting to " + url);
				}
				response.setHeader("Location", url);
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
			} else {
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.sendError(HttpServletResponse.SC_BAD_REQUEST, "{\"error\": \"request must be over https\"}");
			}
		}
	}

	class UaaLoggingFilter implements Filter {
		final Log logger = LogFactory.getLog(getClass());
		protected final String name;

		UaaLoggingFilter(String name) {
			this.name = name;
		}

		public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
			HttpServletRequest request = (HttpServletRequest)req;
			HttpServletResponse response = (HttpServletResponse) res;

			if (logger.isDebugEnabled()) {
				logger.debug("Filter chain '" + name + "' processing request " + request.getMethod() + " " + request.getRequestURI());

				if (dumpRequests) {
					logger.debug(dumpRequest(request));
				}
			}

			chain.doFilter(request, response);
		}

		@SuppressWarnings("unchecked")
		protected final String dumpRequest(HttpServletRequest r) {
			StringBuilder builder = new StringBuilder(256);
			builder.append("\n    ").append(r.getMethod()).append(" ").append(r.getRequestURI()).append("\n");
			Enumeration<String> e = r.getHeaderNames();

			while(e.hasMoreElements()) {
				String hdrName = e.nextElement();
				Enumeration<String> values = r.getHeaders(hdrName);

				while (values.hasMoreElements()) {
					builder.append("    ").append(hdrName).append(": ").append(values.nextElement()).append("\n");
				}
			}
			return builder.toString();
		}

		public void init(FilterConfig filterConfig) throws ServletException {
		}

		public void destroy() {
		}
	}
}


