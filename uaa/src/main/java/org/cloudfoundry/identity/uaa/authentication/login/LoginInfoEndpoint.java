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
package org.cloudfoundry.identity.uaa.authentication.login;

import java.security.Principal;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Controller that sends login info (e.g. prompts) to clients wishing to authenticate.
 *
 * @author Dave Syer
 */
@Controller
public class LoginInfoEndpoint {
	
	private List<Prompt> prompts = Arrays.asList(new Prompt("username", "text", "Username"), new Prompt("password", "password", "Password"));

	public void setPrompts(List<Prompt> prompts) {
		this.prompts = prompts;
	}

	@RequestMapping (value = {"/login_info", "/login"})
	public String loginInfo(Model model, Principal principal) {
		Map<String, String[]> map = new LinkedHashMap<String, String[]>();
		for (Prompt prompt : prompts) {
			map.put(prompt.getName(), prompt.getDetails());
		}
		model.addAttribute("prompts", map);
		if (principal==null) {
			return "login";
		}
		return "home";
	}

}
