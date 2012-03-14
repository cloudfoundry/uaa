/**
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

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

	private String userAuthorizationUri = "http://localhost:8080/uaa/oauth/authorize";
	
	private String dataUri = "http://localhost:8080/api/apps";
	
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

	@RequestMapping("/browse")
	public String browse(Model model) {
		model.addAttribute("userAuthorizationUri", userAuthorizationUri);
		model.addAttribute("dataUri", dataUri);
		return "browse";
	}

	@RequestMapping("/home")
	public String home(Model model, Principal principal) {
		model.addAttribute("principal", principal);
		return "home";
	}

}
