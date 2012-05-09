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

import java.util.HashMap;
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
			model.put("message",
					"To confirm or deny access POST to the following locations with the parameters requested.");
			Map<String, Object> options = new HashMap<String, Object>() {
				{
					put("confirm", new HashMap<String, String>() {
						{
							put("location", getLocation(request, "oauth/authorize"));
							put("path", getPath(request, "/oauth/authorize"));
							put("key", "user_oauth_approval");
							put("value", "true");
						}

					});
					put("deny", new HashMap<String, String>() {
						{
							put("location", getLocation(request, "oauth/authorize"));
							put("path", getPath(request, "/oauth/authorize"));
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

	protected String getLocation(HttpServletRequest request, String path) {
		return extractScheme(request) + "://" + request.getHeader("Host") + getPath(request, path);
	}

	private String getPath(HttpServletRequest request, String path) {
		return request.getContextPath() + "/" + path;
	}

	protected String extractScheme(HttpServletRequest request) {
		return useSsl != null && useSsl ? "https" : request.getScheme();
	}

}
