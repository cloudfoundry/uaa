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
import java.nio.charset.Charset;
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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.SocialClientUserDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.login.AutologinRequest;
import org.cloudfoundry.identity.uaa.login.AutologinResponse;
import org.cloudfoundry.identity.uaa.login.PasscodeInformation;
import org.cloudfoundry.identity.uaa.login.SamlUserDetails;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

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

    private AuthenticationManager authenticationManager;

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

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
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

    @RequestMapping(value = {"/login" }, headers = "Accept=application/json")
    public String loginForJson(Model model, Principal principal) {
        return login(model, principal, Collections.<String>emptyList(), false);
    }

    @RequestMapping(value = {"/info" }, headers = "Accept=application/json")
    public String infoForJson(Model model, Principal principal) {
        return login(model, principal, Collections.<String>emptyList(), true);
    }

    @RequestMapping(value = {"/info" }, headers = "Accept=text/html, */*")
    public String infoForHtml(Model model, Principal principal) {
        return login(model, principal, Arrays.asList("passcode"), false);
    }

    @RequestMapping(value = {"/login" }, headers = "Accept=text/html, */*")
    public String loginForHtml(Model model, Principal principal) {
        return login(model, principal, Arrays.asList("passcode"), false);
    }

    public String login(Model model, Principal principal, List<String> excludedPrompts, boolean nonHtml) {
        populatePrompts(model, excludedPrompts, nonHtml);
        setCommitInfo(model);
        model.addAttribute("zone_name", IdentityZoneHolder.get().getName());
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
            if (selfServiceLinksEnabled && (!nonHtml)) {
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


    public void populatePrompts(Model model, List<String> exclude, boolean nonHtml) {
        Map<String, String[]> map = new LinkedHashMap<>();
        List<Map<String,String>> list = new LinkedList<>();
        for (Prompt prompt : prompts) {
            if (!exclude.contains(prompt.getName())) {
                if (nonHtml) {
                    Map<String, String> promptmap = new LinkedHashMap<>();
                    promptmap.put("name", prompt.getName());
                    promptmap.put("type", prompt.getDetails()[0]);
                    promptmap.put("text", prompt.getDetails()[1]);
                    list.add(promptmap);
                } else {
                    map.put(prompt.getName(), prompt.getDetails());
                }
            }
        }
        if (nonHtml) {
            model.addAttribute("prompts", list);
        } else {
            model.addAttribute("prompts", map);
        }

    }


    @RequestMapping(value = "/autologin", method = RequestMethod.POST)
    @ResponseBody
    public AutologinResponse generateAutologinCode(@RequestBody AutologinRequest request,
                                                   @RequestHeader(value = "Authorization", required = false) String auth) throws Exception {
        if (auth == null || (!auth.startsWith("Basic"))) {
            throw new BadCredentialsException("No basic authorization client information in request");
        }

        String username = request.getUsername();
        if (username == null) {
            throw new BadCredentialsException("No username in request");
        }
        Authentication userAuthentication = null;
        if (authenticationManager != null) {
            String password = request.getPassword();
            if (!StringUtils.hasText(password)) {
                throw new BadCredentialsException("No password in request");
            }
            userAuthentication = authenticationManager.authenticate(new AuthzAuthenticationRequest(username, password, null));
        }

        String base64Credentials = auth.substring("Basic".length()).trim();
        String credentials = new String(new Base64().decode(base64Credentials.getBytes()), Charset.forName("UTF-8"));
        // credentials = username:password
        final String[] values = credentials.split(":", 2);
        if (values == null || values.length == 0) {
            throw new BadCredentialsException("Invalid authorization header.");
        }
        String clientId = values[0];
        SocialClientUserDetails user = new SocialClientUserDetails(username, UaaAuthority.USER_AUTHORITIES);
        Map<String,String> details = new HashMap<>();
        details.put("client_id", clientId);
        user.setDetails(details);
        if (userAuthentication!=null && userAuthentication.getPrincipal() instanceof UaaPrincipal) {
            UaaPrincipal p = (UaaPrincipal)userAuthentication.getPrincipal();
            if (p!=null) {
                details.put(Origin.ORIGIN, p.getOrigin());
                details.put("user_id",p.getId());
            }
        }

        ExpiringCode response = doGenerateCode(user);
        return new AutologinResponse(response.getCode());
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
