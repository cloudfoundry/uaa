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
package org.cloudfoundry.identity.app.web;

import java.net.URI;
import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestOperations;

@Controller
public class HomeController {

	private String userAuthorizationUri = "http://localhost:8080/uaa/oauth/authorize";

	private String dataUri = "http://localhost:8080/api/apps";

	private String clientId = "app";

	private RestOperations restTemplate;

	private String logoutUrl;

	public void setRestTemplate(RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	/**
	 * @param logoutUrl the logoutUrl to set
	 */
	public void setLogoutUrl(String logoutUrl) {
		this.logoutUrl = logoutUrl;
	}

	/**
	 * @param userAuthorizationUri the userAuthorizationUri to set
	 */
	public void setUserAuthorizationUri(String userAuthorizationUri) {
		this.userAuthorizationUri = userAuthorizationUri;
	}

	/**
	 * @param userInfoUri the userInfoUri to set
	 */
	public void setDataUri(String dataUri) {
		this.dataUri = dataUri;
	}

	/**
	 * @param clientId the clientId to set
	 */
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	@RequestMapping("/browse")
	public String browse(Model model) {
		model.addAttribute("userAuthorizationUri", userAuthorizationUri);
		model.addAttribute("clientId", clientId);
		model.addAttribute("dataUri", dataUri);
		return "browse";
	}

	@RequestMapping("/home")
	public String home(Model model, Principal principal) {
		model.addAttribute("principal", principal);
		return "home";
	}

	// Home page with just the user id - useful for testing simplest possible use case
	@RequestMapping("/id")
	public String id(Model model, Principal principal) {
		model.addAttribute("principal", principal);
		return "home";
	}

	@RequestMapping("/revoke")
	public String revoke(Model model, Principal principal) {
		URI azUri = URI.create(userAuthorizationUri);
		String port = azUri.getPort() == 80 ? "" : ":" + azUri.getPort();
		String approvalURL = azUri.getScheme() + "://" + azUri.getHost() + port + "/login/approvals";

		return "redirect:" + approvalURL;
	}

	@RequestMapping("/logout")
	public String logout(Model model, HttpServletRequest request) {
		String redirect = request.getRequestURL().toString();
		model.addAttribute("cflogout", logoutUrl + "?redirect=" + redirect);
		return "loggedout";
	}

}
