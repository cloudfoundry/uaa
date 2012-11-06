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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Custom request matcher which allows endpoints in the UAA to be matched as substrings and also differentiation based
 * on the content type (e.g. JSON vs HTML) specified in the Accept request header, thus allowing different filter chains
 * to be configured for browser and command-line clients.
 * <p>
 * Currently just looks for a match of the configured MIME-type in the accept header when deciding whether to match the
 * request. There is no parsing of priorities in the header.
 */
public final class UaaRequestMatcher implements RequestMatcher {

	private static final Log logger = LogFactory.getLog(UaaRequestMatcher.class);

	private final String path;

	private List<MediaType> accepts;

	private HttpMethod method;

	private Map<String, String> parameters = new HashMap<String, String>();

	public UaaRequestMatcher(String path) {
		Assert.hasText(path);
		if (path.contains("*")) {
			throw new IllegalArgumentException("UaaRequestMatcher is not intended for use with wildcards");
		}
		this.path = path;
	}

	/**
	 * The HttpMethod that the request should be made with. Optional (if null, then all values match)
	 *
	 * @param method
	 */
	public void setMethod(HttpMethod method) {
		this.method = method;
	}

	/**
	 * A media type that should be present in the accept header for a request to match. Optional (if null then all
	 * values match).
	 * 
	 * @param accepts the accept header value to set
	 */
	public void setAccept(List<MediaType> accepts) {
		this.accepts = Collections.unmodifiableList(accepts);
	}

	/**
	 * A map of request parameter name and values to match against. If all the specified parameters are present and
	 * match the values given then the accept header will be ignored.
	 * 
	 * @param parameters the parameter matches to set
	 */
	public void setParameters(Map<String, String> parameters) {
		this.parameters = parameters;
	}

	public boolean matches(HttpServletRequest request) {

		String message = "";
		if (logger.isDebugEnabled()) {
			message = request.getRequestURI() + "'; '" + request.getContextPath() + path + "' with parameters="
					+ parameters;
			logger.debug("Checking match of request : '" + message);
		}

		if (!request.getRequestURI().startsWith(request.getContextPath() + path)) {
			return false;
		}

		if (method != null && !method.toString().equals(request.getMethod().toUpperCase())) {
			return false;
		}

		boolean parameterMatch = true;
		for (String key : parameters.keySet()) {
			String value = request.getParameter(key);
			parameterMatch &= value != null ? value.startsWith(parameters.get(key)) : false;
		}
		if (accepts == null && parameterMatch) {
			if (logger.isDebugEnabled()) {
				logger.debug("Matched request (no check for accept): '" + message);
			}
			return true;
		}

		if (request.getHeader("Accept") == null && parameterMatch) {
			if (logger.isDebugEnabled()) {
				logger.debug("Matched request (no accept header): '" + message);
			}
			return true;
		}

		// TODO: Use mime-type priorities
		for (MediaType acceptHeader : MediaType.parseMediaTypes(request.getHeader("Accept"))) {
			for (MediaType accept : accepts) {
				if (acceptHeader.includes(accept) && parameterMatch) {
					if (logger.isDebugEnabled()) {
						logger.debug("Matched request (acceptable media type): '" + message);
					}
					return true;
				}
			}
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Unmatched request : '" + message);
		}
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof UaaRequestMatcher)) {
			return false;
		}
		UaaRequestMatcher other = (UaaRequestMatcher) obj;
		if (!this.path.equals(other.path)) {
			return false;
		}

		if (this.method != null && other.method != null && this.method != other.method) {
			return false;
		}

		if (this.parameters == null) {
			return true;
		}

		if (this.accepts == null) {
			return true;
		}

		return this.accepts.equals(other.accepts) && this.parameters.equals(other.parameters);
	}

	@Override
	public int hashCode() {
		int code = 31 ^ path.hashCode();
		if (method != null) {
			code ^= method.hashCode();
		}
		if (accepts != null) {
			code ^= accepts.hashCode();
		}
		if (parameters != null) {
			code ^= parameters.hashCode();
		}
		return code;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("UAAPath ['").append(path).append("'");

		if (accepts != null) {
			sb.append(", ").append(accepts);
		}

		sb.append("]");

		return sb.toString();
	}
}
