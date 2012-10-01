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
package org.cloudfoundry.identity.uaa.oauth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.context.request.WebRequest;

/**
 * Controller for retrieving the model for and displaying the confirmation page for access to a protected resource.
 * 
 * @author Dave Syer
 */
@Controller
@SessionAttributes("authorizationRequest")
public class AccessController {

	private static final String SCOPE_PREFIX = "scope.";

	private ClientDetailsService clientDetailsService;

	private Boolean useSsl;

	/**
	 * Explicitly requests caller to point back to an authorization endpoint on "https", even if the incoming request is
	 * "http" (e.g. when downstream of the SSL termination behind a load balancer).
	 * 
	 * @param useSsl the flag to set (null to use the incoming request to determine the URL scheme)
	 */
	public void setUseSsl(Boolean useSsl) {
		this.useSsl = useSsl;
	}

	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	@RequestMapping("/oauth/confirm_access")
	public String confirm(Map<String, Object> model, final HttpServletRequest request) throws Exception {

		AuthorizationRequest clientAuth = (AuthorizationRequest) model.remove("authorizationRequest");
		if (clientAuth == null) {
			model.put("error",
					"No authorization request is present, so we cannot confirm access (we don't know what you are asking for).");
			// response.sendError(HttpServletResponse.SC_BAD_REQUEST);
		}
		else {
			BaseClientDetails client = new BaseClientDetails(clientDetailsService.loadClientByClientId(clientAuth.getClientId()));
			client.setClientSecret(null);
			model.put("auth_request", clientAuth);
			model.put("client", client); // TODO: remove this once it has gone from jsp pages
			model.put("client_id", clientAuth.getClientId());
			model.put("redirect_uri", getRedirectUri(client, clientAuth));
			model.put("scopes", getScopes(client, clientAuth));
			model.put("message",
					"To confirm or deny access POST to the following locations with the parameters requested.");
			Map<String, Object> options = new HashMap<String, Object>() {
				{
					put("confirm", new HashMap<String, String>() {
						{
							put("location", getLocation(request, "oauth/authorize"));
							put("path", getPath(request, "oauth/authorize"));
							put("key", "user_oauth_approval");
							put("value", "true");
						}

					});
					put("deny", new HashMap<String, String>() {
						{
							put("location", getLocation(request, "oauth/authorize"));
							put("path", getPath(request, "oauth/authorize"));
							put("key", "user_oauth_approval");
							put("value", "false");
						}

					});
				}
			};
			model.put("options", options);
		}
		return "access_confirmation";

	}

	private List<Map<String, String>> getScopes(ClientDetails client, AuthorizationRequest clientAuth) {
		List<Map<String, String>> result = new ArrayList<Map<String, String>>();
		for (String scope : clientAuth.getScope()) {
			if (!scope.contains(".")) {
				HashMap<String, String> map = new HashMap<String, String>();
				map.put("code", SCOPE_PREFIX + scope);
				map.put("text", "Access your data with scope '" + scope + "'");
				result.add(map);
			}
			else {
				HashMap<String, String> map = new HashMap<String, String>();
				String value = SCOPE_PREFIX + scope;
				String resource = scope.substring(0, scope.lastIndexOf("."));
				if ("uaa".equals(resource)) {
					// special case: don't need to prompt for internal uaa scopes
					continue;
				}
				String access = scope.substring(scope.lastIndexOf(".") + 1);
				map.put("code", value);
				map.put("text", "Access your '" + resource + "' resources with scope '" + access + "'");
				result.add(map);
			}
		}
		Collections.sort(result, new Comparator<Map<String, String>>() {
			@Override
			public int compare(Map<String, String> o1, Map<String, String> o2) {
				String code1 = o1.get("code");
				String code2 = o2.get("code");
				if (code1.startsWith(SCOPE_PREFIX + "password") || code1.startsWith(SCOPE_PREFIX + "openid")) {
					code1 = "aaa" + code1;
				}
				if (code2.startsWith(SCOPE_PREFIX + "password") || code2.startsWith(SCOPE_PREFIX + "openid")) {
					code2 = "aaa" + code2;
				}
				return code1.compareTo(code2);
			}
		});
		return result;
	}

	private String getRedirectUri(ClientDetails client, AuthorizationRequest clientAuth) {
		String result = null;
		if (clientAuth.getRedirectUri() != null) {
			result = clientAuth.getRedirectUri();
		}
		if (client.getRegisteredRedirectUri() != null && !client.getRegisteredRedirectUri().isEmpty() && result == null) {
			result = client.getRegisteredRedirectUri().iterator().next();
		}
		if (result != null) {
			if (result.contains("?")) {
				result = result.substring(0, result.indexOf("?"));
			}
			if (result.contains("#")) {
				result = result.substring(0, result.indexOf("#"));
			}
		}
		return result;
	}

	@RequestMapping("/oauth/error")
	public String handleError(WebRequest request, Map<String,Object> model) throws Exception {
		// There is already an error entry in the model
		Object object = request.getAttribute("error", WebRequest.SCOPE_REQUEST);
		if (object!=null) {
			model.put("error", object);
		}
		return "access_confirmation";
	}

	protected String getLocation(HttpServletRequest request, String path) {
		return extractScheme(request) + "://" + request.getHeader("Host") + getPath(request, path);
	}

	private String getPath(HttpServletRequest request, String path) {
		String contextPath = request.getContextPath();
		if (contextPath.endsWith("/")) {
			contextPath = contextPath.substring(0, contextPath.lastIndexOf("/") - 1);
		}
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		return contextPath + "/" + path;
	}

	protected String extractScheme(HttpServletRequest request) {
		return useSsl != null && useSsl ? "https" : request.getScheme();
	}

}
