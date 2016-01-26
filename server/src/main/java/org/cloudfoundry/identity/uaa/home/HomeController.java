/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.home;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.client.ClientMetadata;
import org.cloudfoundry.identity.uaa.client.JdbcClientMetadataProvisioning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class HomeController {
    private final Log logger = LogFactory.getLog(getClass());
    protected final Environment environment;
    private Map<String, String> links = new HashMap<String, String>();
    private String baseUrl;

    @Autowired
    private JdbcClientMetadataProvisioning clientMetadataProvisioning;

    public HomeController(Environment environment) {
        this.environment = environment;
    }

    /**
     * @param links the links to set
     */
    public void setLinks(Map<String, String> links) {
        this.links = links;
    }

    public Map<String, String> getLinks() {
        return links;
    }

    /**
     * @param baseUrl the base uaa url
     */
    public void setUaaBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    protected String getUaaBaseUrl() {
        return baseUrl;
    }

    protected Map<String, ?> getLinksInfo() {
        Map<String, Object> model = new HashMap<String, Object>();
        model.put(OriginKeys.UAA, getUaaBaseUrl());
        model.put("login", getUaaBaseUrl().replaceAll(OriginKeys.UAA, "login"));
        model.putAll(getLinks());
        return model;
    }

    protected void populateBuildAndLinkInfo(Model model) {
        Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("links", getLinksInfo());
        model.addAllAttributes(attributes);
        model.addAttribute("links", getLinks());
    }

    @RequestMapping(value = { "/", "/home" })
    public String home(Model model, Principal principal) {
        String homePage = environment.getProperty("login.homeRedirect");
        if (homePage != null) {
            return "redirect:" + homePage;
        }
        model.addAttribute("principal", principal);
        if (IdentityZoneHolder.isUaa()) {
            List<ClientMetadata> clientMetadataList = clientMetadataProvisioning.retrieveAll();
            List<ClientMetadata> showClientMetadataList = clientMetadataList.stream().filter(clientMetadata -> clientMetadata.isShowOnHomePage()).collect(Collectors.toList());
            model.addAttribute("tiles", showClientMetadataList);
        }
        boolean invitationsEnabled = "true".equalsIgnoreCase(environment.getProperty("login.invitationsEnabled"));
        if (invitationsEnabled) {
            model.addAttribute("invitationsLink", "/invitations/new");
        }
        populateBuildAndLinkInfo(model);
        return "home";
    }

    @RequestMapping("/error500")
    public String error500(Model model, HttpServletRequest request) {
        logger.error("Internal error", (Throwable) request.getAttribute("javax.servlet.error.exception"));

        populateBuildAndLinkInfo(model);
        return "error";
    }

    @RequestMapping("/error404")
    public String error404(Model model) {
        populateBuildAndLinkInfo(model);
        return "error";
    }

    @RequestMapping("/saml_error")
    public String error401(Model model, HttpServletRequest request) {
        AuthenticationException exception = (AuthenticationException) request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        model.addAttribute("saml_error", exception.getMessage());
        return "saml_error";
    }
}
