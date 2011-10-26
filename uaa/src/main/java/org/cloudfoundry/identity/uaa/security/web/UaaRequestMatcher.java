package org.cloudfoundry.identity.uaa.security.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

/**
 * Custom request matcher which allows endpoints in the UAA to be matched as
 * substrings and also differentiation based on the content type (e.g. JSON vs HTML) specified in the Accept
 * request header, thus allowing different filter chains to be configured for browser and command-line
 * clients.
 * <p>
 * Currently just looks for a match of the configured MIME-type in the accept header when deciding
 * whether to match the request. There is no parsing of priorities in the header.
 */
public final class UaaRequestMatcher implements RequestMatcher {
	private static final Log logger = LogFactory.getLog(UaaRequestMatcher.class);

	private final String path;
	private final String accept;

	public UaaRequestMatcher(String path) {
		this(path, null);
	}

	public UaaRequestMatcher(String path, String accept) {
		Assert.hasText(path);
		if (path.contains("*")) {
			throw new IllegalArgumentException("UaaRequestMatcher is not intended for use with wildcards");
		}
		this.path=path;
		this.accept = accept;
	}

	public boolean matches(HttpServletRequest request) {
		if (logger.isDebugEnabled()) {
			logger.debug("Checking match of request : '" + request.getRequestURI() + "'; against '" +
								 request.getContextPath() + path + "'");
		}

		if (!request.getRequestURI().startsWith(request.getContextPath() + path)) {
			return false;
		}

		if (accept == null) {
			return true;
		}

		// Naive check for now. Return a match if no accept header or it contains the configured type
		// TODO: Use mime-type priorities
		String acceptHeader = request.getHeader("Accept");
		return acceptHeader == null || acceptHeader.contains(accept);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof UaaRequestMatcher)) {
			return false;
		}
		UaaRequestMatcher other = (UaaRequestMatcher)obj;
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
