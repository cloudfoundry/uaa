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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestOperations;

@Controller
public class TreeController {

	private RestOperations restTemplate;

	private String treeUrlPattern;

	public void setRestTemplate(RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	public void setTreeUrlPattern(String treeUrlPattern) {
		this.treeUrlPattern = treeUrlPattern;
	}

	@RequestMapping("/apps")
	public String apps(Model model, Principal principal) throws Exception {
		loadItems(model, "apps");
		addUserInfo(model, principal);
		return "tree";
	}

	private void addUserInfo(Model model, Principal principal) {
		model.addAttribute("principal", principal);
		Map<String,String> attributes = new HashMap<String, String>();
		if (principal instanceof OpenIDAuthenticationToken) {
			for (OpenIDAttribute attr : ((OpenIDAuthenticationToken) principal).getAttributes()) {
				List<String> values = attr.getValues();
				String value = values.isEmpty() ? "" : values.get(0);
				attributes.put(attr.getName(), value);
			}
		}
		model.addAttribute("attributes", attributes);
	}

	private void loadItems(Model model, String type) throws Exception {
		List<Map<String, Object>> items = getItems(type);
		model.addAttribute("items", items);
		model.addAttribute("name", StringUtils.capitalize(type));
		model.addAttribute("title", "Your " + StringUtils.capitalize(type));		
	}

	private List<Map<String, Object>> getItems(String type) throws Exception {
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> result = restTemplate.getForObject(treeUrlPattern, List.class, type);
		return result;
	}

}
