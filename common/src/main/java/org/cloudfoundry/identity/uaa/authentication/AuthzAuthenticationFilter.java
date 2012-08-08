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
package org.cloudfoundry.identity.uaa.authentication;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * Filter which processes authentication submitted through the <code>/authorize</code> endpoint.
 * 
 * Checks the submitted information for a parameter named "credentials" (or specified via the
 * {@link #setParameterNames(List) parameter name}), in JSON format.
 * <p>
 * If the parameter is found, it will submit an authentication request to the AuthenticationManager and attempt to
 * authenticate the user. If authentication fails, it will return an error message. Otherwise, it creates a security
 * context and allows the request to continue.
 * <p>
 * If the parameter is not present, the filter will have no effect.
 * 
 * See <a href="https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.md">UUA API Docs</a>
 */
public class AuthzAuthenticationFilter implements Filter {

	private final Log logger = LogFactory.getLog(getClass());

	private AuthenticationManager authenticationManager;

	private ObjectMapper mapper = new ObjectMapper();

	private List<String> parameterNames = Collections.EMPTY_LIST;// = "credentials";

	/**
	 * The name of the parameter to extract credentials from.
	 * 
	 * @param parameterNames the parameter names to set (default "credentials")
	 */
	public void setParameterNames(List<String> parameterNames) {
		this.parameterNames = parameterNames;
	}

	public AuthzAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager);
		this.authenticationManager = authenticationManager;
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {

		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;

		if (!"POST".equals(req.getMethod().toUpperCase())) {
			throw new BadCredentialsException("Credentials must be sent via POST");
		}

		Map<String, String> loginInfo = getCredentials(req);

		if (loginInfo.isEmpty()) {
			logger.debug("Request does not contain credentials. Ignoring.");
		} else {
			try {
				Authentication result = authenticationManager.authenticate(new AuthzAuthenticationRequest(loginInfo,
						new UaaAuthenticationDetails(req)));
				SecurityContextHolder.getContext().setAuthentication(result);
			}
			catch (AuthenticationException e) {
				logger.debug("Authentication failed");
				response.getWriter().write("{ \"error\":\"authentication failed\" }");
				response.setContentType("application/json");
				res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
		}

		chain.doFilter(request, response);
	}

	private Map<String, String> getCredentials(HttpServletRequest request) {
		Map<String, String> credentials = new HashMap<String, String>();

		for (String paramName : parameterNames) {
			String value = request.getParameter(paramName);
			if (value != null) {
				if (value.startsWith("{")) {
					try {
						Map<String, String> jsonCredentials = mapper.readValue(value, new TypeReference<Map<String, String>>() {
						});
						credentials.putAll(jsonCredentials);
					} catch (IOException e) {
						logger.warn("Unknown format of value for request param: " + paramName + ". Ignoring.");
					}
				} else {
					credentials.put(paramName, value);
				}
			}
		}

		logger.debug("Located credentials in request, with keys: " + credentials.keySet());
		return credentials;
	}

	public void init(FilterConfig filterConfig) throws ServletException {
	}

	public void destroy() {
	}
}
