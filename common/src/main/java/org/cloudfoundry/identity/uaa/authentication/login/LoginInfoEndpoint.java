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
package org.cloudfoundry.identity.uaa.authentication.login;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Controller that sends login info (e.g. prompts) to clients wishing to
 * authenticate.
 * 
 * @author Dave Syer
 */
@Controller
public class LoginInfoEndpoint {

    private Properties gitProperties = new Properties();

    private Properties buildProperties = new Properties();

    private Map<String, String> links = new HashMap<String, String>();

    private String baseUrl;

    private String uaaHost;

    public LoginInfoEndpoint() {
        try {
            gitProperties = PropertiesLoaderUtils.loadAllProperties("git.properties");
        } catch (IOException e) {
            // Ignore
        }
        try {
            buildProperties = PropertiesLoaderUtils.loadAllProperties("build.properties");
        } catch (IOException e) {
            // Ignore
        }
    }

    private List<Prompt> prompts = Arrays.asList(new Prompt("username", "text", "Email"), new Prompt("password",
                    "password", "Password"));

    public void setPrompts(List<Prompt> prompts) {
        this.prompts = prompts;
    }

    @RequestMapping(value = {"/login" })
    public String login(Model model, Principal principal) {
        Map<String, String[]> map = new LinkedHashMap<String, String[]>();
        for (Prompt prompt : prompts) {
            map.put(prompt.getName(), prompt.getDetails());
        }
        model.addAttribute("prompts", map);
        model.addAttribute("commit_id", gitProperties.getProperty("git.commit.id.abbrev", "UNKNOWN"));
        model.addAttribute(
                        "timestamp",
                        gitProperties.getProperty("git.commit.time",
                                        new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())));
        model.addAttribute("app", UaaStringUtils.getMapFromProperties(buildProperties, "build."));
        model.addAttribute("links", getLinksInfo());

        if (principal == null) {
            return "login";
        }
        return "home";
    }

    @RequestMapping("/info")
    public String info(Model model, Principal principal) {
        String result = login(model, principal);
        List<Map<String, String>> list = new ArrayList<Map<String, String>>();
        for (Prompt prompt : prompts) {
            Map<String, String> map = new LinkedHashMap<String, String>();
            map.put("name", prompt.getName());
            map.put("type", prompt.getDetails()[0]);
            map.put("text", prompt.getDetails()[1]);
            list.add(map);
        }
        model.addAttribute("prompts", list);
        return result;
    }

    protected Map<String, ?> getLinksInfo() {
        Map<String, Object> model = new HashMap<String, Object>();
        model.put("uaa", getUaaBaseUrl());
        model.put("login", getUaaBaseUrl().replaceAll("uaa", "login"));
        model.putAll(getLinks());
        return model;
    }

    public void setUaaBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
        try {
            URI uri = new URI(baseUrl);
            setUaaHost(uri.getHost());
            if (uri.getPort()!=443 && uri.getPort()!=80 && uri.getPort()>0) {
                //append non standard ports to the hostname
                setUaaHost(getUaaHost()+":"+uri.getPort());
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Could not extract host from URI: " + baseUrl);
        }
    }

    public Map<String, String> getLinks() {
        return links;
    }

    public void setLinks(Map<String, String> links) {
        this.links = links;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    protected String getUaaBaseUrl() {
        return baseUrl;
    }

    public String getUaaHost() {
        return uaaHost;
    }

    public void setUaaHost(String uaaHost) {
        this.uaaHost = uaaHost;
    }
}
