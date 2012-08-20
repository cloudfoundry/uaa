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

package org.cloudfoundry.identity.uaa.impersonate;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class ImpersonateSwitchFilter implements Filter {

	private static final class SwitcherServletRequestWrapper extends HttpServletRequestWrapper {
		private final String clientId;

		private final String userId;

		private SwitcherServletRequestWrapper(ServletRequest request, String clientId, String userId) {
			super((HttpServletRequest) request);
			this.clientId = clientId;
			this.userId = userId;
		}

		@Override
		public String getParameter(String name) {
			if ("impersonator_user_id".equals(name) && userId != null) {
				return userId;
			}
			if ("impersonator_client_id".equals(name)) {
				return clientId;
			}
			return super.getParameter(name);
		}

		@Override
		public String[] getParameterValues(String name) {
			if ("impersonator_user_id".equals(name) && userId != null) {
				return new String[] { userId };
			}
			if ("impersonator_client_id".equals(name)) {
				return new String[] { clientId };
			}
			return super.getParameterValues(name);
		}

		@SuppressWarnings("rawtypes")
		@Override
		public Map getParameterMap() {
			@SuppressWarnings("unchecked")
			Map<String, String[]> map = new LinkedHashMap<String, String[]>(super.getParameterMap());
			map.put("impersonator_client_id", new String[] { clientId });
			if (userId != null) {
				map.put("impersonator_user_id", new String[] { userId });
			}
			return map;
		}
	}

	private final UaaUserDatabase userDatabase;

	public ImpersonateSwitchFilter(UaaUserDatabase userDatabase) {
		this.userDatabase = userDatabase;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		// Now we check for an incoming authentication request to the token endpoint
		if (!(authentication instanceof OAuth2Authentication) || !authentication.isAuthenticated()) {
			throw new BadCredentialsException("Request is not authenticated with client credentials");
		}

		String userId = ((OAuth2Authentication) authentication).isClientOnly() ? null
				: ((OAuth2Authentication) authentication).getUserAuthentication().getName();
		String clientId = ((OAuth2Authentication) authentication).getAuthorizationRequest().getClientId();

		@SuppressWarnings("unchecked")
		DefaultAuthorizationRequest authorizationRequest = new DefaultAuthorizationRequest(
				getSingleValuedMap(request.getParameterMap()));
		authorizationRequest.setApproved(true);
		UaaUser user = userDatabase.retrieveUserByName(request.getParameter("username"));
		UaaAuthentication userAuthentication = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(),
				new UaaAuthenticationDetails((HttpServletRequest) request));

		SecurityContextHolder.getContext().setAuthentication(
				new ImpersonateAuthenticationToken(new OAuth2Authentication(authorizationRequest, userAuthentication)));

		chain.doFilter(new SwitcherServletRequestWrapper(request, clientId, userId), response);

	}

	private Map<String, String> getSingleValuedMap(Map<String, String[]> parameters) {
		Map<String, String> map = new HashMap<String, String>();
		for (String key : parameters.keySet()) {
			String[] values = parameters.get(key);
			if (values != null && values.length > 0) {
				map.put(key, values[0]);
			}
			else {
				map.put(key, null);
			}
		}
		return map;
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void destroy() {
	}

}
