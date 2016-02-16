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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.SamlRedirectUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.isNull;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;
import static org.springframework.util.StringUtils.hasText;

/**
 * Controller that sends login info (e.g. prompts) to clients wishing to
 * authenticate.
 *
 * @author Dave Syer
 */
@Controller
public class LoginInfoEndpoint {

    public static final String NotANumber = OriginKeys.NotANumber;
    public static final String CREATE_ACCOUNT_LINK = "createAccountLink";
    public static final String FORGOT_PASSWORD_LINK = "forgotPasswordLink";
    public static final String LINK_CREATE_ACCOUNT_SHOW = "linkCreateAccountShow";
    public static final String FIELD_USERNAME_SHOW = "fieldUsernameShow";

    public static final List<String> UI_ONLY_ATTRIBUTES =
        Collections.unmodifiableList(
            Arrays.asList(CREATE_ACCOUNT_LINK, FORGOT_PASSWORD_LINK, LINK_CREATE_ACCOUNT_SHOW, FIELD_USERNAME_SHOW)
        );
    public static final String PASSCODE = "passcode";
    public static final String SHOW_SAML_LOGIN_LINKS = "showSamlLoginLinks";
    public static final String LINKS = "links";
    public static final String ZONE_NAME = "zone_name";
    public static final String ENTITY_ID = "entityID";
    public static final String IDP_DEFINITIONS = "idpDefinitions";

    private Properties gitProperties = new Properties();

    private Properties buildProperties = new Properties();

    private String baseUrl;

    private String externalLoginUrl;

    private String samlSPBaseUrl;

    private String uaaHost;

    private SamlIdentityProviderConfigurator idpDefinitions;

    private long codeExpirationMillis = 5 * 60 * 1000;

    private AuthenticationManager authenticationManager;

    private ExpiringCodeStore expiringCodeStore;
    private ClientDetailsService clientDetailsService;

    private IdentityProviderProvisioning providerProvisioning;

    public void setExpiringCodeStore(ExpiringCodeStore expiringCodeStore) {
        this.expiringCodeStore = expiringCodeStore;
    }

    public long getCodeExpirationMillis() {
        return codeExpirationMillis;
    }

    public void setCodeExpirationMillis(long codeExpirationMillis) {
        this.codeExpirationMillis = codeExpirationMillis;
    }

    public void setIdpDefinitions(SamlIdentityProviderConfigurator idpDefinitions) {
        this.idpDefinitions = idpDefinitions;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    private String entityID = "";

    public void setEntityID(String entityID) {
        this.entityID = entityID;
    }

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

    @RequestMapping(value = {"/login"}, headers = "Accept=application/json")
    public String loginForJson(Model model, Principal principal) {
        return login(model, principal, Collections.<String>emptyList(), true);
    }

    @RequestMapping(value = {"/info"}, headers = "Accept=application/json")
    public String infoForJson(Model model, Principal principal) {
        return login(model, principal, Collections.<String>emptyList(), true);
    }

    @RequestMapping(value = {"/info"}, headers = "Accept=text/html, */*")
    public String infoForHtml(Model model, Principal principal) {
        return login(model, principal, Arrays.asList(PASSCODE), false);
    }

    @RequestMapping(value = {"/login"}, headers = "Accept=text/html, */*")
    public String loginForHtml(Model model, Principal principal, HttpServletRequest request) {
        return login(model, principal, Arrays.asList(PASSCODE), false, request);
    }

    @RequestMapping(value = {"/invalid_request"})
    public String invalidRequest(HttpServletRequest request) {
        return "invalid_request";
    }

    protected String getZonifiedEntityId() {
        return SamlRedirectUtils.getZonifiedEntityId(entityID);
    }

    private String login(Model model, Principal principal, List<String> excludedPrompts, boolean jsonResponse) {
        return login(model, principal, excludedPrompts, jsonResponse, null);
    }

    private String login(Model model, Principal principal, List<String> excludedPrompts, boolean jsonResponse, HttpServletRequest request) {
        HttpSession session = request != null ? request.getSession(false) : null;
        List<String> allowedIdps = getAllowedIdps(session);

        List<SamlIdentityProviderDefinition> idps = getSamlIdentityProviderDefinitions(allowedIdps);

        boolean fieldUsernameShow = true;

        IdentityProvider ldapIdentityProvider = null;
        try {
            ldapIdentityProvider = providerProvisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException e) {
        }
        IdentityProvider uaaIdentityProvider = providerProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        //ldap and uaa disabled
        if (!uaaIdentityProvider.isActive()) {
            if (ldapIdentityProvider == null || !ldapIdentityProvider.isActive()) {
                fieldUsernameShow = false;
            }
        }

        //ldap or uaa not part of allowedIdps
        if (allowedIdps != null) {
            if ((!allowedIdps.contains(OriginKeys.LDAP) &&
                !allowedIdps.contains(OriginKeys.UAA) &&
                !allowedIdps.contains(OriginKeys.KEYSTONE))) {
                fieldUsernameShow = false;
            }
        }

        if(!fieldUsernameShow) {
            if (idps != null && idps.size() == 1) {
                String url = SamlRedirectUtils.getIdpRedirectUrl(idps.get(0), entityID);
                return "redirect:" + url;
            }
        }

        boolean linkCreateAccountShow = fieldUsernameShow;
        if (fieldUsernameShow && (allowedIdps != null && !allowedIdps.contains(OriginKeys.UAA))) {
            linkCreateAccountShow = false;
        }
        String zonifiedEntityID = getZonifiedEntityId();
        Map links = getLinksInfo();
        if (jsonResponse) {
            for (String attribute : UI_ONLY_ATTRIBUTES) {
                links.remove(attribute);
            }
            Map<String, String> idpDefinitionsForJson = new HashMap<>();
            if (idps != null) {
                for (SamlIdentityProviderDefinition def : idps) {
                    String idpUrl = links.get("login") +
                        String.format("/saml/discovery?returnIDParam=idp&entityID=%s&idp=%s&isPassive=true",
                                      zonifiedEntityID,
                                      def.getIdpEntityAlias());
                    idpDefinitionsForJson.put(def.getIdpEntityAlias(), idpUrl);
                }
                model.addAttribute(IDP_DEFINITIONS, idpDefinitionsForJson);
            }
        } else {
            model.addAttribute(LINK_CREATE_ACCOUNT_SHOW, linkCreateAccountShow);
            model.addAttribute(FIELD_USERNAME_SHOW, fieldUsernameShow);
            model.addAttribute(IDP_DEFINITIONS, idps);
        }
        model.addAttribute(LINKS, links);
        setCommitInfo(model);
        model.addAttribute(ZONE_NAME, IdentityZoneHolder.get().getName());

        // Entity ID to start the discovery
        model.addAttribute(ENTITY_ID, zonifiedEntityID);
        boolean noSamlIdpsPresent = true;
        for (SamlIdentityProviderDefinition idp : idps) {
            if (idp.isShowSamlLink()) {
                model.addAttribute(SHOW_SAML_LOGIN_LINKS, true);
                noSamlIdpsPresent = false;
                break;
            }
        }
        //make the list writeable
        excludedPrompts = new LinkedList<>(excludedPrompts);
        if (noSamlIdpsPresent) {
            excludedPrompts.add(PASSCODE);
        }

        populatePrompts(model, excludedPrompts, jsonResponse);

        if (principal == null) {
            return "login";
        }
        return "home";
    }

    protected List<SamlIdentityProviderDefinition> getSamlIdentityProviderDefinitions(List<String> allowedIdps) {
        return idpDefinitions.getIdentityProviderDefinitions(allowedIdps, IdentityZoneHolder.get());
    }

    protected boolean hasSavedOauthAuthorizeRequest(HttpSession session) {
        if (session == null || session.getAttribute("SPRING_SECURITY_SAVED_REQUEST") == null) {
            return false;
        }
        SavedRequest savedRequest = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        String redirectUrl = savedRequest.getRedirectUrl();
        String[] client_ids = savedRequest.getParameterValues("client_id");
        if (redirectUrl != null && redirectUrl.contains("/oauth/authorize") && client_ids != null && client_ids.length != 0) {
            return true;
        }
        return false;
    }

    public List<String> getAllowedIdps(HttpSession session) {
        if (!hasSavedOauthAuthorizeRequest(session)) {
            return null;
        }
        SavedRequest savedRequest = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        String[] client_ids = savedRequest.getParameterValues("client_id");
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(client_ids[0]);
            return (List<String>) clientDetails.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS);
        } catch (NoSuchClientException x) {
            return null;
        }
    }

    private void setCommitInfo(Model model) {
        model.addAttribute("commit_id", gitProperties.getProperty("git.commit.id.abbrev", "UNKNOWN"));
        model.addAttribute(
            "timestamp",
            gitProperties.getProperty("git.commit.time",
                                      new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date())));
        model.addAttribute("app", UaaStringUtils.getMapFromProperties(buildProperties, "build."));
    }


    public void populatePrompts(Model model, List<String> exclude, boolean jsonResponse) {
        IdentityZoneConfiguration zoneConfiguration = IdentityZoneHolder.get().getConfig();
        if (isNull(zoneConfiguration)) {
            zoneConfiguration = new IdentityZoneConfiguration();
        }
        Map<String, String[]> map = new LinkedHashMap<>();
        for (Prompt prompt : zoneConfiguration.getPrompts()) {
            if (!exclude.contains(prompt.getName())) {
                String[] details = prompt.getDetails();
                if (PASSCODE.equals(prompt.getName()) && !IdentityZoneHolder.isUaa()) {
                    String urlInPasscode = extractUrlFromString(prompt.getDetails()[1]);
                    if (hasText(urlInPasscode)) {
                        String[] newDetails = new String[details.length];
                        System.arraycopy(details, 0, newDetails, 0, details.length);
                        newDetails[1] = newDetails[1].replace(urlInPasscode, addSubdomainToUrl(urlInPasscode));
                        details = newDetails;
                    }
                }
                map.put(prompt.getName(), details);
            }
        }
        model.addAttribute("prompts", map);
    }

    //http://stackoverflow.com/questions/5713558/detect-and-extract-url-from-a-string
    // Pattern for recognizing a URL, based off RFC 3986
    private static final Pattern urlPattern = Pattern.compile(
        "((https?|ftp|gopher|telnet|file):((//)|(\\\\))+[\\w\\d:#@%/;$()~_?\\+-=\\\\\\.&]*)",
        Pattern.CASE_INSENSITIVE );

    public String extractUrlFromString(String s) {
        Matcher matcher = urlPattern.matcher(s);
        if (matcher.find()) {
            int matchStart = matcher.start(0);
            int matchEnd = matcher.end(0);
            // now you have the offsets of a URL match
            return s.substring(matchStart, matchEnd);
        }
        return null;
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
            if (!hasText(password)) {
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
        Map<String, String> codeData = new HashMap<>();
        codeData.put("client_id", clientId);
        codeData.put("username", username);
        codeData.put("action", ExpiringCodeType.AUTOLOGIN.name());
        if (userAuthentication!=null && userAuthentication.getPrincipal() instanceof UaaPrincipal) {
            UaaPrincipal p = (UaaPrincipal)userAuthentication.getPrincipal();
            if (p!=null) {
                codeData.put("user_id", p.getId());
                codeData.put(OriginKeys.ORIGIN, p.getOrigin());
            }
        }
        ExpiringCode expiringCode = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000), null);

        return new AutologinResponse(expiringCode.getCode());
    }

    @RequestMapping(value = "/autologin", method = RequestMethod.GET)
    public String performAutologin(HttpSession session) {
        String redirectLocation = "home";
        SavedRequest savedRequest = (SavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        if (savedRequest != null && savedRequest.getRedirectUrl() != null) {
            redirectLocation = savedRequest.getRedirectUrl();
        }

        return "redirect:" + redirectLocation;
    }

    @RequestMapping(value = { "/passcode" }, method = RequestMethod.GET)
    public String generatePasscode(Map<String, Object> model, Principal principal)
        throws NoSuchAlgorithmException, IOException {
        String username, origin, userId = NotANumber;
        Map<String, Object> authorizationParameters = null;

        if (principal instanceof UaaPrincipal) {
            UaaPrincipal uaaPrincipal = (UaaPrincipal)principal;
            username = uaaPrincipal.getName();
            origin = uaaPrincipal.getOrigin();
            userId = uaaPrincipal.getId();
        } else if (principal instanceof UaaAuthentication) {
            UaaPrincipal uaaPrincipal = ((UaaAuthentication)principal).getPrincipal();
            username = uaaPrincipal.getName();
            origin = uaaPrincipal.getOrigin();
            userId = uaaPrincipal.getId();
        } else if (principal instanceof LoginSamlAuthenticationToken) {
            username = principal.getName();
            origin = ((LoginSamlAuthenticationToken) principal).getUaaPrincipal().getOrigin();
            userId = ((LoginSamlAuthenticationToken) principal).getUaaPrincipal().getId();
        } else if (principal instanceof Authentication && ((Authentication)principal).getPrincipal() instanceof UaaPrincipal) {
            UaaPrincipal uaaPrincipal = (UaaPrincipal)((Authentication)principal).getPrincipal();
            username = uaaPrincipal.getName();
            origin = uaaPrincipal.getOrigin();
            userId = uaaPrincipal.getId();
        } else {
            throw new UnknownPrincipalException();
        }

        PasscodeInformation pi = new PasscodeInformation(userId, username, null, origin, authorizationParameters);

        String intent = "PASSCODE " + pi.getUserId();

        expiringCodeStore.expireByIntent(intent);

        ExpiringCode code = expiringCodeStore.generateCode(
            JsonUtils.writeValueAsString(pi),
            new Timestamp(System.currentTimeMillis() + (getCodeExpirationMillis())),
            intent);

        model.put(PASSCODE, code.getCode());

        return PASSCODE;
    }

    protected Map<String, ?> getLinksInfo() {
        IdentityZone zone = IdentityZoneHolder.get();
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = providerProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        boolean disableInternalUserManagement = (uaaIdp.getConfig()!=null) ? uaaIdp.getConfig().isDisableInternalUserManagement() : false;
        boolean selfServiceLinksEnabled = (zone.getConfig()!=null) ? zone.getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled() : true;
        String signup = zone.getConfig()!=null ? zone.getConfig().getLinks().getSelfService().getSignup() : null;
        String passwd = zone.getConfig()!=null ? zone.getConfig().getLinks().getSelfService().getPasswd() : null;
        Map<String, Object> model = new HashMap<>();
        model.put(OriginKeys.UAA, addSubdomainToUrl(getUaaBaseUrl()));
        if (getBaseUrl().contains("localhost:")) {
            model.put("login", addSubdomainToUrl(getUaaBaseUrl()));
        } else if (hasText(getExternalLoginUrl())){
            model.put("login", getExternalLoginUrl());
        } else {
            model.put("login", addSubdomainToUrl(getUaaBaseUrl().replaceAll(OriginKeys.UAA, "login")));
        }
        if (selfServiceLinksEnabled && !disableInternalUserManagement) {
            model.put(CREATE_ACCOUNT_LINK, "/create_account");
            model.put("register", "/create_account");
            model.put(FORGOT_PASSWORD_LINK, "/forgot_password");
            model.put("passwd", "/forgot_password");
            if(IdentityZoneHolder.isUaa()) {
                if (hasText(signup)) {
                    model.put(CREATE_ACCOUNT_LINK, signup);
                    model.put("register", signup);
                }
                if (hasText(passwd)) {
                    model.put(FORGOT_PASSWORD_LINK, passwd);
                    model.put("passwd", passwd);
                }
            }
        }
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

    public void setExternalLoginUrl(String baseUrl) {
        this.externalLoginUrl = baseUrl;
    }

    public String getExternalLoginUrl() {
        return externalLoginUrl;
    }

    public String getSamlSPBaseUrl() {
        return samlSPBaseUrl;
    }

    public void setSamlSPBaseUrl(String samlSPBaseUrl) {
        this.samlSPBaseUrl = samlSPBaseUrl;
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

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public IdentityProviderProvisioning getProviderProvisioning() {
        return providerProvisioning;
    }

    public void setProviderProvisioning(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    @ResponseStatus(value = HttpStatus.FORBIDDEN, reason = "Unknown authentication token type, unable to derive user ID.")
    public static final class UnknownPrincipalException extends RuntimeException {}

}
