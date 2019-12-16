/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.app.web;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestOperations;

@Controller
public class TreeController {

    private RestOperations restTemplate;

    private String treeUrlPattern = "http://localhost:8080/api/apps";

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
        Map<String, String> attributes = new HashMap<String, String>();
        if (principal instanceof SocialClientUserDetails) {
            SocialClientUserDetails user = (SocialClientUserDetails) principal;
            model.addAttribute("userName", user.getUsername());
            model.addAttribute("email", user.getEmail());
        }
        model.addAttribute("attributes", attributes);
    }

    private void loadItems(Model model, String type) {
        List<Map<String, Object>> items = getItems(type);
        model.addAttribute("items", items);
        model.addAttribute("name", StringUtils.capitalize(type));
        model.addAttribute("title", "Your " + StringUtils.capitalize(type));
    }

    private List<Map<String, Object>> getItems(String type) {
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> result = restTemplate.getForObject(treeUrlPattern, List.class, type);
        return result;
    }

}
