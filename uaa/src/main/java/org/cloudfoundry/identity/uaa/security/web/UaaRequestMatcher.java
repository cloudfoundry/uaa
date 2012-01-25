/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.security.web;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

	private MediaType accept;

	private Map<String, String> parameters = new HashMap<String, String>();

	public UaaRequestMatcher(String path) {
		Assert.hasText(path);
		if (path.contains("*")) {
			throw new IllegalArgumentException("UaaRequestMatcher is not intended for use with wildcards");
		}
		this.path = path;
	}

	/**
	 * A media type that should be present in the accept header for a request to match. Optional (if null then all
	 * values match).
	 * 
	 * @param accept the accept header value to set
	 */
	public void setAccept(MediaType accept) {
		this.accept = accept;
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
		if (logger.isDebugEnabled()) {
			logger.debug("Checking match of request : '" + request.getRequestURI() + "'; against '"
					+ request.getContextPath() + path + "'");
		}

		if (!request.getRequestURI().startsWith(request.getContextPath() + path)) {
			return false;
		}

		boolean parameterMatch = false;
		for (String key : parameters.keySet()) {
			String value = request.getParameter(key);
			parameterMatch = value != null ? value.startsWith(parameters.get(key)) : false;
		}
		if (accept == null || parameterMatch) {
			return true;
		}

		if (request.getHeader("Accept") == null) {
			return true;
		}

		// TODO: Use mime-type priorities and expect a list of media types
		MediaType acceptHeader = MediaType.parseMediaType(request.getHeader("Accept"));
		return acceptHeader == null || acceptHeader.includes(accept);
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

		if (this.accept == null) {
			return true;
		}

		return this.accept.equals(other.accept);
	}

	@Override
	public int hashCode() {
		int code = 31 ^ path.hashCode();
		if (accept != null) {
			code ^= accept.hashCode();
		}
		return code;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("UAAPath ['").append(path).append("'");

		if (accept != null) {
			sb.append(", ").append(accept);
		}

		sb.append("]");

		return sb.toString();
	}
}
