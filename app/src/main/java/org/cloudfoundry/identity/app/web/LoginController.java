/*
 * Copyright 2006-2010 the original author or authors.
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
package org.cloudfoundry.identity.app.web;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LoginController {

	private String openidProviderUrl;
	
	public void setOpenidProviderUrl(String openidProviderUrl) {
		this.openidProviderUrl = openidProviderUrl;
	}
	
	@RequestMapping("/openid")
	public String login(Model model) {
		model.addAttribute("action", "verify");
		model.addAttribute("openid_identifier", openidProviderUrl);
		model.addAttribute("_spring_security_remember_me", "true");
		return "redirect:j_spring_openid_security_check";
	}

	@RequestMapping("/home")
	public String home(Model model, Principal principal) {
		model.addAttribute("principal", principal);
		return "home";
	}

}
