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
import javax.servlet.http.HttpServletRequestWrapper;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

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
public class SecurityFilterChainPostProcessor implements BeanPostProcessor {
	private final Log logger = LogFactory.getLog(getClass());
	private boolean requireHttps = false;
	private String httpsHeader = "HTTP_X_FORWARDED_PROTO";
	private String requiredHttpsHeaderValue = "https";
	private String clientAddrHeader = "HTTP_X_CLUSTER_CLIENT_IP";
	private List<String> redirectToHttps = Collections.emptyList();
	private boolean dumpRequests = false;

	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		if (bean instanceof SecurityFilterChain) {
			logger.info("Processing security filter chain " + beanName);

			SecurityFilterChain fc = (SecurityFilterChain)bean;

			if (!fc.getFilters().isEmpty()) {
				Filter uaaFilter;

				if (requireHttps) {
					uaaFilter = new HttpsEnforcementFilter(beanName, redirectToHttps.contains(beanName));
				} else {
					uaaFilter = new UaaRequestWrapperFilter(beanName);
				}
				fc.getFilters().add(0, uaaFilter);
			}
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
	public void setDumpRequests(boolean dumpRequests) {
		this.dumpRequests = dumpRequests;
	}

	/**
	 * The header to check for to determine whether the request was made over HTTPS
	 * or not. If the <tt>requiredHttpsHeaderValue</tt> property is set, the header value is checked
	 * to make sure it matches. If the property is not set, it is assumed that the presence of the
	 * header is sufficient to guarantee that the connection is secure.
	 *
	 * @param httpsHeader
	 */
	public void setHttpsHeader(String httpsHeader) {
		Assert.hasText(httpsHeader);
		this.httpsHeader = httpsHeader;
	}

	public void setRequiredHttpsHeaderValue(String requiredHttpsHeaderValue) {
		this.requiredHttpsHeaderValue = requiredHttpsHeaderValue;
	}

	public void setClientAddrHeader(String clientAddrHeader) {
		Assert.hasText(clientAddrHeader);
		this.clientAddrHeader = clientAddrHeader;
	}

	public void setRedirectToHttps(List<String> redirectToHttps) {
		this.redirectToHttps = redirectToHttps;
	}

	final class HttpsEnforcementFilter extends UaaRequestWrapperFilter {
		private final int httpsPort = 443;
		private final boolean redirect;

		HttpsEnforcementFilter(String name, boolean redirect) {
			super(name);
			this.redirect = redirect;
		}

		public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
			HttpServletRequest request = (HttpServletRequest) req;
			HttpServletResponse response = (HttpServletResponse) res;

			final boolean isHttps = isSecure(request);

			if (isHttps) {
				// Ok. Just pass on.
				if (redirect) {
					// Set HSTS header for browser clients
					response.setHeader("Strict-Transport-Security", "max-age=31536000");
				}
				super.doFilter(req, response, chain);
				return;
			}

			if (redirect) {
				RedirectUrlBuilder rb = new RedirectUrlBuilder();
				rb.setScheme("https");
				rb.setPort(httpsPort);
				rb.setContextPath(request.getContextPath());
				rb.setServletPath(request.getServletPath());
				rb.setPathInfo(request.getPathInfo());
				rb.setQuery(request.getQueryString());
				// Send a 301 as suggested by
				// http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec-14#section-7.2
				response.setHeader("Location", rb.getUrl());
				response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
			} else {
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				response.sendError(HttpServletResponse.SC_BAD_REQUEST, "{\"error\": \"request must be over https\"}");
			}
		}
	}

	class UaaRequestWrapperFilter implements Filter {
		final Log logger = LogFactory.getLog(UaaRequestWrapperFilter.class);

		protected final String name;

		UaaRequestWrapperFilter(String name) {
			if (requireHttps) {
				Assert.hasText(requiredHttpsHeaderValue, "requiredHttpsHeaderValue must be set if https is required");
			}
			this.name = name;
		}

		public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
			HttpServletRequest request = new RequestWrapper((HttpServletRequest)req);
			HttpServletResponse response = (HttpServletResponse) res;

			if (logger.isDebugEnabled()) {
				logger.debug("Filter chain '" + name + "' processing request " + request.getMethod() + " " + request.getRequestURI());

				if (dumpRequests) {
					logger.debug(dumpHeaders(request));
				}
			}

			chain.doFilter(request, response);
		}

		@SuppressWarnings("unchecked")
		private String dumpHeaders(HttpServletRequest r) {
			StringBuilder builder = new StringBuilder(256);
			builder.append("Headers:\n");
			Enumeration<String> e = r.getHeaderNames();

			while(e.hasMoreElements()) {
				String hdrName = e.nextElement();
				Enumeration<String> values = r.getHeaders(hdrName);

				while (values.hasMoreElements()) {
					builder.append(" ").append(hdrName).append(": ").append(values.nextElement()).append("\n");
				}
			}
			return builder.toString();
		}

		public void init(FilterConfig filterConfig) throws ServletException {
		}

		public void destroy() {
		}

		/**
		 * For now we assume that the specified header may not be present and must have the
		 * given value to indicate that a request is secure.
		 */
		boolean isSecure(HttpServletRequest request) {
			String secureHeader = request.getHeader(httpsHeader);
			logger.debug("Https header is " + secureHeader);
			return requiredHttpsHeaderValue != null && requiredHttpsHeaderValue.equalsIgnoreCase(secureHeader);
		}

		class RequestWrapper extends HttpServletRequestWrapper {

			public RequestWrapper(HttpServletRequest request) {
				super(request);
			}

			public boolean isSecure() {
				if (super.isSecure()) {
					return true;
				}
				return UaaRequestWrapperFilter.this.isSecure((HttpServletRequest)getRequest());
			}

			public String getRemoteAddr() {
				String header = getHeader(clientAddrHeader);

				if (StringUtils.hasText(header)) {
					return header;
				} else {
					logger.debug("Header " + clientAddrHeader + " is not set");
					return super.getRemoteAddr();
				}
			}
		}

	}
}


