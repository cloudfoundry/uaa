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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;

/**
 * Controller for retrieving the model for and displaying the confirmation page for access to a protected resource.
 * 
 * @author Dave Syer
 */
@Controller
@SessionAttributes(types = AuthorizationRequest.class)
public class AccessController {

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

	@ModelAttribute("identity")
	public String getIdentity(HttpSession session) {
		return null;
	}

	@RequestMapping("/oauth/confirm_access")
	public String confirm(@ModelAttribute AuthorizationRequest clientAuth, Map<String, Object> model,
			final HttpServletRequest request) throws Exception {

		if (clientAuth == null) {
			model.put("error",
					"No authorizatioun request is present, so we cannot confirm access (we don't know what you are asking for).");
			// response.sendError(HttpServletResponse.SC_BAD_REQUEST);
		}
		else {
			ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
			model.put("auth_request", clientAuth);
			model.put("client", client);
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
			if (scope.equals("openid")) {
				HashMap<String, String> map = new HashMap<String, String>();
				map.put("code", scope);
				map.put("text", "Access your profile including email address");
				result.add(map);
			}
			else if (scope.equals("password")) {
				HashMap<String, String> map = new HashMap<String, String>();
				map.put("code", scope);
				map.put("text", "Change your password");
				result.add(map);
			}
			else {
				for (String resource : client.getResourceIds()) {
					if (resource.equals("password") || resource.equals("openid")) {
						continue;
					}
					HashMap<String, String> map = new HashMap<String, String>();
					String value = resource + "." + scope;
					map.put("code", value);
					map.put("text", "Access your '" + resource + "' resources with scope '" + scope + "'");
					result.add(map);
				}
			}
		}
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
	public String handleError() throws Exception {
		// There is already an error entry in the model
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
