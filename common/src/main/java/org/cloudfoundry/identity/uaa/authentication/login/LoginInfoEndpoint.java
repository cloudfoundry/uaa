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

import javax.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.login.PasscodeInformation;
import org.cloudfoundry.identity.uaa.login.SamlUserDetails;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Controller that sends login info (e.g. prompts) to clients wishing to
 * authenticate.
 * 
 * @author Dave Syer
 */
@Controller
public class LoginInfoEndpoint {

    public static final String NotANumber = Origin.NotANumber;

    private Properties gitProperties = new Properties();

    private Properties buildProperties = new Properties();

    private Map<String, String> links = new HashMap<String, String>();

    private String baseUrl;

    private String uaaHost;

    protected Environment environment;

    private List<IdentityProviderDefinition> idpDefinitions;

    private long codeExpirationMillis = 5 * 60 * 1000;

    private ExpiringCodeStore expiringCodeStore;

    public void setExpiringCodeStore(ExpiringCodeStore expiringCodeStore) {
        this.expiringCodeStore = expiringCodeStore;
    }

    public long getCodeExpirationMillis() {
        return codeExpirationMillis;
    }

    public void setCodeExpirationMillis(long codeExpirationMillis) {
        this.codeExpirationMillis = codeExpirationMillis;
    }

    public void setIdpDefinitions(List<IdentityProviderDefinition> idpDefinitions) {
        this.idpDefinitions = idpDefinitions;
    }

    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Value("${login.entityID}")
    public String entityID = "";

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

    /**
     * This was the handler for the branded login page in login-server
     * @param model
     * @param principal
     * @return
     */
    @RequestMapping(value = { "/info", "/login" }, method = RequestMethod.GET, produces = APPLICATION_JSON_VALUE, headers = "Accept=application/json")
    public String prompts(HttpServletRequest request, @RequestHeader HttpHeaders headers, Model model,
                          Principal principal) throws Exception {

        populatePrompts(model, Collections.<String>emptyList());
        // Entity ID to start the discovery
        model.addAttribute("entityID", entityID);
        model.addAttribute("idpDefinitions", idpDefinitions);
        model.addAttribute("links", getLinksInfo());
        setCommitInfo(model);
        if (principal == null) {
            return "login";
        }
        return "home";
    }

    /**
     * This was the handler for the unbranded login page in UAA
     * @param model
     * @param principal
     * @return
     */
    @RequestMapping(value = {"/login", "/info" })
    public String login(Model model, Principal principal) {
        populatePrompts(model, Arrays.asList("passcode"));
        setCommitInfo(model);
        model.addAttribute("links", getLinksInfo());

        // Entity ID to start the discovery
        model.addAttribute("entityID", entityID);
        model.addAttribute("idpDefinitions", idpDefinitions);
        for (IdentityProviderDefinition idp : idpDefinitions) {
            if(idp.isShowSamlLink()) {
                model.addAttribute("showSamlLoginLinks", true);
                break;
            }
        }

        if (principal == null) {
            boolean selfServiceLinksEnabled = !"false".equalsIgnoreCase(environment.getProperty("login.selfServiceLinksEnabled"));
            if (selfServiceLinksEnabled) {
                String customSignupLink = environment.getProperty("links.signup");
                String customPasswordLink = environment.getProperty("links.passwd");
                if (StringUtils.hasText(customSignupLink)) {
                    model.addAttribute("createAccountLink", customSignupLink);
                } else {
                    model.addAttribute("createAccountLink", "/create_account");
                }
                if (StringUtils.hasText(customPasswordLink)) {
                    model.addAttribute("forgotPasswordLink", customPasswordLink);
                } else {
                    model.addAttribute("forgotPasswordLink", "/forgot_password");
                }
            }
            return "login";
        }
        return "home";
    }

    private void setCommitInfo(Model model) {
        model.addAttribute("commit_id", gitProperties.getProperty("git.commit.id.abbrev", "UNKNOWN"));
        model.addAttribute(
                        "timestamp",
                        gitProperties.getProperty("git.commit.time",
                                        new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())));
        model.addAttribute("app", UaaStringUtils.getMapFromProperties(buildProperties, "build."));
    }


    public void populatePrompts(Model model, List<String> exclude) {
        Map<String, String[]> map = new LinkedHashMap<>();
        for (Prompt prompt : prompts) {
            if (!exclude.contains(prompt.getName())) {
                map.put(prompt.getName(), prompt.getDetails());
            }
        }

        model.addAttribute("prompts", map);
    }

    @RequestMapping(value = { "/passcode" }, method = RequestMethod.GET)
    public String generatePasscode(@RequestHeader HttpHeaders headers, Map<String, Object> model, Principal principal)
        throws NoSuchAlgorithmException, IOException, JsonMappingException {
        String username = null, origin = null, userId = NotANumber;
        Map<String, Object> authorizationParameters = null;

        if (principal instanceof LoginSamlAuthenticationToken) {
            username = principal.getName();
            origin = ((LoginSamlAuthenticationToken)principal).getUaaPrincipal().getOrigin();
            userId = ((LoginSamlAuthenticationToken)principal).getUaaPrincipal().getId();
            //TODO collect authorities here?
        } else if (principal instanceof ExpiringUsernameAuthenticationToken) {
            username = ((SamlUserDetails) ((ExpiringUsernameAuthenticationToken) principal).getPrincipal()).getUsername();
            origin = "login-saml";
            Collection<GrantedAuthority> authorities = ((SamlUserDetails) (((ExpiringUsernameAuthenticationToken) principal)
                .getPrincipal())).getAuthorities();
            if (authorities != null) {
                authorizationParameters = new LinkedHashMap<>();
                authorizationParameters.put("authorities", authorities);
            }
        } else {
            username = principal.getName();
            origin = "passcode";
        }

        PasscodeInformation pi = new PasscodeInformation(userId, username, null, origin, authorizationParameters);

        ExpiringCode code = doGenerateCode(pi);
        model.put("passcode", code.getCode());
        return "passcode";
    }

    protected ExpiringCode doGenerateCode(Object o) throws IOException {
        return expiringCodeStore.generateCode(
            new ObjectMapper().writeValueAsString(o),
            new Timestamp(System.currentTimeMillis() + (getCodeExpirationMillis()))
        );
    }


    protected Map<String, ?> getLinksInfo() {
        Map<String, Object> model = new HashMap<>();
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

    protected String extractPath(HttpServletRequest request) {
        String query = request.getQueryString();
        try {
            query = query == null ? "" : "?" + URLDecoder.decode(query, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Cannot decode query string: " + query);
        }
        String path = request.getRequestURI() + query;
        String context = request.getContextPath();
        path = path.substring(context.length());
        if (path.startsWith("/")) {
            // In the root context we have to remove this as well
            path = path.substring(1);
        }
        return path;
    }

}
