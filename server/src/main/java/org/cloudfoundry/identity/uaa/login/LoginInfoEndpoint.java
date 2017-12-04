/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents wit
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.SamlRedirectUtils;
import org.cloudfoundry.identity.uaa.util.ColorHash;
import org.cloudfoundry.identity.uaa.util.DomainFilter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils.JsonUtilException;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.HttpMediaTypeNotAcceptableException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.awt.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
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
import java.util.Optional;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyMap;
import static java.util.Objects.isNull;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

/**
 * Controller that sends login info (e.g. prompts) to clients wishing to
 * authenticate.
 *
 * @author Dave Syer
 */
@Controller
public class LoginInfoEndpoint {

    private static Log logger = LogFactory.getLog(LoginInfoEndpoint.class);

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
    public static final String SHOW_LOGIN_LINKS = "showLoginLinks";
    public static final String LINKS = "links";
    public static final String ZONE_NAME = "zone_name";
    public static final String ENTITY_ID = "entityID";
    public static final String IDP_DEFINITIONS = "idpDefinitions";
    public static final String OAUTH_LINKS = "oauthLinks";

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
    private ClientServicesExtension clientDetailsService;

    private IdentityProviderProvisioning providerProvisioning;
    private MapCollector<IdentityProvider, String, AbstractXOAuthIdentityProviderDefinition> idpsMapCollector =
        new MapCollector<>(
            idp -> idp.getOriginKey(),
            idp ->  (AbstractXOAuthIdentityProviderDefinition) idp.getConfig()
        );

    private XOAuthProviderConfigurator xoAuthProviderConfigurator;

    private Links globalLinks = new Links().setSelfService(new Links.SelfService().setPasswd(null).setSignup(null));

    public void setGlobalLinks(Links globalLinks) {
        this.globalLinks = globalLinks;
    }

    public LoginInfoEndpoint setXoAuthProviderConfigurator(XOAuthProviderConfigurator xoAuthProviderConfigurator) {
        this.xoAuthProviderConfigurator = xoAuthProviderConfigurator;
        return this;
    }

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
    public String loginForJson(Model model, Principal principal, HttpServletRequest request) {
        return login(model, principal, Collections.emptyList(), true, request);
    }

    @RequestMapping(value = {"/info"}, headers = "Accept=application/json")
    public String infoForJson(Model model, Principal principal, HttpServletRequest request) {
        return login(model, principal, Collections.emptyList(), true, request);
    }

    @RequestMapping(value = {"/info"}, headers = "Accept=text/html, */*")
    public String infoForHtml(Model model, Principal principal, HttpServletRequest request) {
        return login(model, principal, Collections.singletonList(PASSCODE), false, request);
    }

    static class SavedAccountOptionModel extends SavedAccountOption {
        public int red, green, blue;
        public void assignColors(Color color) {
            red = color.getRed();
            blue = color.getBlue();
            green = color.getGreen();
        }
    }

    @RequestMapping(value = {"/login"}, headers = "Accept=text/html, */*")
    public String loginForHtml(
        Model model, Principal principal, HttpServletRequest request,
        @RequestHeader(value = "Accept", required = false) List<MediaType> headers)
        throws HttpMediaTypeNotAcceptableException
    {
        boolean match = headers == null || headers.stream().anyMatch(mediaType -> mediaType.isCompatibleWith(MediaType.TEXT_HTML));
        if (!match) {
            throw new HttpMediaTypeNotAcceptableException(request.getHeader(HttpHeaders.ACCEPT));
        }

        Cookie[] cookies = request.getCookies();
        List<SavedAccountOptionModel> savedAccounts = getSavedAccounts(cookies, SavedAccountOptionModel.class);
        savedAccounts.forEach(account -> {
            Color color = ColorHash.getColor(account.getUserId());
            account.assignColors(color);
        });

        model.addAttribute("savedAccounts", savedAccounts);

        return login(model, principal, Collections.singletonList(PASSCODE), false, request);
    }

    private static <T extends SavedAccountOption> List<T> getSavedAccounts(Cookie[] cookies, Class<T> clazz) {
        return Arrays.asList(ofNullable(cookies).orElse(new Cookie[]{}))
                .stream()
                .filter(c -> c.getName().startsWith("Saved-Account"))
                .map(c -> {
                    try { return JsonUtils.readValue(decodeCookieValue(c.getValue()), clazz); }
                    catch (JsonUtilException e) { return null; }
                })
                .filter(c -> c != null)
                .collect(Collectors.toList());
    }

    private static String decodeCookieValue(String inValue) {
        String out = null;
        try {
            out = URLDecoder.decode(inValue, UTF_8.name());
        } catch (Exception e) {
            logger.debug("URLDecoder.decode failed for " + inValue, e);
            return "";
        }
        return out;
    }

    @RequestMapping(value = {"/invalid_request"})
    public String invalidRequest(HttpServletRequest request) {
        return "invalid_request";
    }

    protected String getZonifiedEntityId() {
        return SamlRedirectUtils.getZonifiedEntityId(entityID);
    }

    private String login(Model model, Principal principal, List<String> excludedPrompts, boolean jsonResponse, HttpServletRequest request) {
        if(principal instanceof UaaAuthentication && ((UaaAuthentication)principal).isAuthenticated()) { return "redirect:/home"; }

        HttpSession session = request != null ? request.getSession(false) : null;
        List<String> allowedIdps = null;
        String clientName = null;
        Map<String,Object> clientInfo;
        if((clientInfo = getClientInfo(session)) != null) {
            allowedIdps = (List<String>) clientInfo.get(ClientConstants.ALLOWED_PROVIDERS);
            clientName = (String) clientInfo.get(ClientConstants.CLIENT_NAME);
        }

        Map<String, SamlIdentityProviderDefinition> samlIdps = getSamlIdentityProviderDefinitions(allowedIdps);
        Map<String, AbstractXOAuthIdentityProviderDefinition> oauthIdentityProviderDefinitions = getOauthIdentityProviderDefinitions(allowedIdps);
        Map<String, AbstractIdentityProviderDefinition> combinedIdps = new HashMap<>();
        combinedIdps.putAll(samlIdps);
        combinedIdps.putAll(oauthIdentityProviderDefinitions);

        boolean fieldUsernameShow = true;
        boolean returnLoginPrompts = true;

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
                returnLoginPrompts = false;
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

        Map.Entry<String, AbstractIdentityProviderDefinition> idpForRedirect = null;

        Optional<String> loginHintParam =
            ofNullable(session)
            .flatMap(s -> ofNullable((SavedRequest) s.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE)))
            .flatMap(sr -> ofNullable(sr.getParameterValues("login_hint")))
            .flatMap(lhValues -> Arrays.asList(lhValues).stream().findFirst());

        if(loginHintParam.isPresent()) {
            String loginHint = loginHintParam.get();

                List<Map.Entry<String, AbstractIdentityProviderDefinition>> matchingIdps = combinedIdps.entrySet().stream().filter(idp -> idp.getValue().getEmailDomain().contains(loginHint)).collect(Collectors.toList());
                if(matchingIdps.size() > 1) {
                    throw new IllegalStateException("There is a misconfiguration with the identity provider(s). Please contact your system administrator.");
                }

            if(matchingIdps.size() == 1) {
                idpForRedirect = matchingIdps.get(0);
            }
        }

        if(idpForRedirect == null && !jsonResponse && !fieldUsernameShow && combinedIdps.size() == 1) {
            idpForRedirect = combinedIdps.entrySet().stream().findAny().get();
        }

        String externalRedirect;

        if (idpForRedirect != null && (externalRedirect = redirectToExternalProvider(idpForRedirect.getValue(), idpForRedirect.getKey(), request)) != null) {
            return externalRedirect;
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
            if (samlIdps != null) {
                for (SamlIdentityProviderDefinition def : samlIdps.values()) {
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
            model.addAttribute(IDP_DEFINITIONS, samlIdps.values());
            Map<String, String> oauthLinks = new HashMap<>();
            ofNullable(oauthIdentityProviderDefinitions).orElse(emptyMap()).entrySet().stream()
                .filter(e -> e.getValue().isShowLinkText())
                .forEach(e ->
                    oauthLinks.put(
                        xoAuthProviderConfigurator.getCompleteAuthorizationURI(
                            e.getKey(),
                            UaaUrlUtils.getBaseURL(request),
                            e.getValue()),
                        e.getValue().getLinkText()
                    )
                );
            model.addAttribute(OAUTH_LINKS, oauthLinks);
            model.addAttribute("clientName", clientName);
        }
        model.addAttribute(LINKS, links);
        setCommitInfo(model);
        model.addAttribute(ZONE_NAME, IdentityZoneHolder.get().getName());

        // Entity ID to start the discovery
        model.addAttribute(ENTITY_ID, zonifiedEntityID);
        boolean noIdpsPresent = true;
        for (SamlIdentityProviderDefinition idp : samlIdps.values()) {
            if (idp.isShowSamlLink()) {
                model.addAttribute(SHOW_LOGIN_LINKS, true);
                noIdpsPresent = false;
                break;
            }
        }

        for (AbstractXOAuthIdentityProviderDefinition oauthIdp : oauthIdentityProviderDefinitions.values()) {
            if (oauthIdp.isShowLinkText()) {
                model.addAttribute(SHOW_LOGIN_LINKS, true);
                noIdpsPresent = false;
                break;
            }
        }

        //make the list writeable
        excludedPrompts = new LinkedList<>(excludedPrompts);
        if (noIdpsPresent) {
            excludedPrompts.add(PASSCODE);
        }

        if(!returnLoginPrompts){
            excludedPrompts.add("username");
            excludedPrompts.add("password");
        }

        populatePrompts(model, excludedPrompts);

        if (principal == null) {

            String formRedirectUri = request.getParameter(UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER);
            if (hasText(formRedirectUri)) {
                model.addAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER, formRedirectUri);
            }

            boolean discoveryEnabled = IdentityZoneHolder.get().getConfig().isIdpDiscoveryEnabled();
            boolean accountChooserEnabled = IdentityZoneHolder.get().getConfig().isAccountChooserEnabled();
            boolean discoveryPerformed = Boolean.parseBoolean(request.getParameter("discoveryPerformed"));
            boolean otherAccountSignIn = Boolean.parseBoolean(request.getParameter("otherAccountSignIn"));
            boolean savedAccountsEmpty = getSavedAccounts(request.getCookies(), SavedAccountOption.class).isEmpty();

            if (discoveryEnabled) {
                boolean accountChooserNeeded = accountChooserEnabled
                    && !(otherAccountSignIn || savedAccountsEmpty)
                    && !discoveryPerformed;

                if (accountChooserNeeded) {
                    return "idp_discovery/account_chooser";
                }

                if (!discoveryPerformed) {
                    return "idp_discovery/email";
                }

                return goToPasswordPage(request.getParameter("email"), model);
            }

            return "login";
        }
        return "home";
    }

    @RequestMapping(value = {"/delete_saved_account"})
    public String deleteSavedAccount(HttpServletRequest request, HttpServletResponse response, String userId) {
        Cookie cookie = new Cookie("Saved-Account-" + userId, "");
        cookie.setMaxAge(0);
        cookie.setPath(request.getContextPath() + "/login");
        response.addCookie(cookie);
        return "redirect:/login";
    }


    private String redirectToExternalProvider(AbstractIdentityProviderDefinition idpForRedirect, String alias, HttpServletRequest request) {
        if(idpForRedirect != null) {
            if (idpForRedirect instanceof SamlIdentityProviderDefinition) {
                String url = SamlRedirectUtils.getIdpRedirectUrl((SamlIdentityProviderDefinition) idpForRedirect, entityID);
                return "redirect:/" + url;
            } else if (idpForRedirect instanceof AbstractXOAuthIdentityProviderDefinition) {
                try {
                    String redirectUrl = getRedirectUrlForXOAuthIDP(request, alias, (AbstractXOAuthIdentityProviderDefinition) idpForRedirect);
                    return "redirect:" + redirectUrl;
                } catch (UnsupportedEncodingException e) {
                }
            }
        }
        return null;
    }

    private String getRedirectUrlForXOAuthIDP(HttpServletRequest request, String alias, AbstractXOAuthIdentityProviderDefinition definition) throws UnsupportedEncodingException {
        return xoAuthProviderConfigurator.getCompleteAuthorizationURI(alias, UaaUrlUtils.getBaseURL(request), definition);
    }

    protected Map<String, SamlIdentityProviderDefinition> getSamlIdentityProviderDefinitions(List<String> allowedIdps) {
        List<SamlIdentityProviderDefinition> filteredIdps = idpDefinitions.getIdentityProviderDefinitions(allowedIdps, IdentityZoneHolder.get());
        return filteredIdps.stream().collect(new MapCollector<>(SamlIdentityProviderDefinition::getUniqueAlias, idp -> idp));
    }

    protected Map<String, AbstractXOAuthIdentityProviderDefinition> getOauthIdentityProviderDefinitions(List<String> allowedIdps) {

        List<IdentityProvider> identityProviders =
            xoAuthProviderConfigurator.retrieveAll(true, IdentityZoneHolder.get().getId());

        Map<String, AbstractXOAuthIdentityProviderDefinition> identityProviderDefinitions = identityProviders.stream()
                .filter(p -> allowedIdps==null || allowedIdps.contains(p.getOriginKey()))
                .collect(idpsMapCollector);
        return identityProviderDefinitions;
    }

    protected boolean hasSavedOauthAuthorizeRequest(HttpSession session) {
        if (session == null || session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE) == null) {
            return false;
        }
        SavedRequest savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        String redirectUrl = savedRequest.getRedirectUrl();
        String[] client_ids = savedRequest.getParameterValues("client_id");
        if (redirectUrl != null && redirectUrl.contains("/oauth/authorize") && client_ids != null && client_ids.length != 0) {
            return true;
        }
        return false;
    }

    public Map<String, Object> getClientInfo(HttpSession session) {
        if (!hasSavedOauthAuthorizeRequest(session)) {
            return null;
        }
        SavedRequest savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        String[] client_ids = savedRequest.getParameterValues("client_id");
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(client_ids[0], IdentityZoneHolder.get().getId());
            return clientDetails.getAdditionalInformation();
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


    public void populatePrompts(Model model, List<String> exclude) {
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

    @RequestMapping(value = "/login/idp_discovery", method = RequestMethod.POST)
    public String discoverIdentityProvider(@RequestParam String email, @RequestParam(required = false) String skipDiscovery, Model model, HttpSession session, HttpServletRequest request) {
        ClientDetails clientDetails = null;
        if (hasSavedOauthAuthorizeRequest(session)) {
            SavedRequest savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
            String[] client_ids = savedRequest.getParameterValues("client_id");
            try {
                clientDetails = clientDetailsService.loadClientByClientId(client_ids[0], IdentityZoneHolder.get().getId());
            } catch (NoSuchClientException e) {
            }
        }
        List<IdentityProvider> identityProviders = DomainFilter.filter(providerProvisioning.retrieveActive(IdentityZoneHolder.get().getId()), clientDetails, email);

        if (!StringUtils.hasText(skipDiscovery) && identityProviders.size() == 1) {
            IdentityProvider matchedIdp = identityProviders.get(0);
            if (matchedIdp.getType().equals(UAA)) {
                return goToPasswordPage(email, model);
            } else {
                String redirectUrl;
                if ((redirectUrl = redirectToExternalProvider(matchedIdp.getConfig(), matchedIdp.getOriginKey(), request)) != null) {
                    return redirectUrl;
                }
            }
        }

        if (StringUtils.hasText(email)) {
            model.addAttribute("email", email);
        }
        return "redirect:/login?discoveryPerformed=true";
    }

    private String goToPasswordPage(String email, Model model) {
        model.addAttribute(ZONE_NAME, IdentityZoneHolder.get().getName());
        model.addAttribute("email", email);
        String forgotPasswordLink;
        if ((forgotPasswordLink = getSelfServiceLinks().get(FORGOT_PASSWORD_LINK)) != null) {
            model.addAttribute(FORGOT_PASSWORD_LINK, forgotPasswordLink);
        }
        return "idp_discovery/password";
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
        String credentials = new String(new Base64().decode(base64Credentials.getBytes()), UTF_8.name());
        // credentials = username:password
        final String[] values = credentials.split(":", 2);
        if (values == null || values.length == 0) {
            throw new BadCredentialsException("Invalid authorization header.");
        }
        String clientId = values[0];
        Map<String, String> codeData = new HashMap<>();
        codeData.put("client_id", clientId);
        codeData.put("username", username);
        if (userAuthentication!=null && userAuthentication.getPrincipal() instanceof UaaPrincipal) {
            UaaPrincipal p = (UaaPrincipal)userAuthentication.getPrincipal();
            if (p!=null) {
                codeData.put("user_id", p.getId());
                codeData.put(OriginKeys.ORIGIN, p.getOrigin());
            }
        }
        ExpiringCode expiringCode = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000), ExpiringCodeType.AUTOLOGIN.name(), IdentityZoneHolder.get().getId());

        return new AutologinResponse(expiringCode.getCode());
    }

    @RequestMapping(value = "/autologin", method = GET)
    public String performAutologin(HttpSession session) {
        String redirectLocation = "home";
        SavedRequest savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        if (savedRequest != null && savedRequest.getRedirectUrl() != null) {
            redirectLocation = savedRequest.getRedirectUrl();
        }

        return "redirect:" + redirectLocation;
    }

    @RequestMapping(value = "/login_implicit", method = GET)
    public String captureImplicitValuesUsingJavascript() {
        return "login_implicit";
    }

    @RequestMapping(value = "/login/callback/{origin}")
    public String handleXOAuthCallback(HttpSession session) {
        String redirectLocation = "/home";
        SavedRequest savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        if (savedRequest != null && savedRequest.getRedirectUrl() != null) {
            redirectLocation = savedRequest.getRedirectUrl();
        }

        return "redirect:" + redirectLocation;
    }

    @RequestMapping(value = { "/passcode" }, method = GET)
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

        String intent = ExpiringCodeType.PASSCODE + " " + pi.getUserId();

        expiringCodeStore.expireByIntent(intent, IdentityZoneHolder.get().getId());

        ExpiringCode code = expiringCodeStore.generateCode(
            JsonUtils.writeValueAsString(pi),
            new Timestamp(System.currentTimeMillis() + (getCodeExpirationMillis())),
            intent, IdentityZoneHolder.get().getId());

        model.put(PASSCODE, code.getCode());

        return PASSCODE;
    }

    protected Map<String, ?> getLinksInfo() {

        Map<String, Object> model = new HashMap<>();
        model.put(OriginKeys.UAA, addSubdomainToUrl(getUaaBaseUrl()));
        if (getBaseUrl().contains("localhost:")) {
            model.put("login", addSubdomainToUrl(getUaaBaseUrl()));
        } else if (hasText(getExternalLoginUrl())){
            model.put("login", getExternalLoginUrl());
        } else {
            model.put("login", addSubdomainToUrl(getUaaBaseUrl().replaceAll(OriginKeys.UAA, "login")));
        }
        model.putAll(getSelfServiceLinks());
        return model;
    }

    protected Map<String,String> getSelfServiceLinks() {
        Map<String, String> selfServiceLinks = new HashMap<>();
        IdentityZone zone = IdentityZoneHolder.get();
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = providerProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        boolean disableInternalUserManagement = (uaaIdp.getConfig()!=null) ? uaaIdp.getConfig().isDisableInternalUserManagement() : false;

        boolean selfServiceLinksEnabled = (zone.getConfig()!=null) ? zone.getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled() : true;

        final String defaultSignup = "/create_account";
        final String defaultPasswd = "/forgot_password";
        Links.SelfService service = zone.getConfig()!=null ? zone.getConfig().getLinks().getSelfService() : null;
        String signup = UaaStringUtils.nonNull(
            service!=null ? service.getSignup() : null,
            globalLinks.getSelfService().getSignup(),
            defaultSignup);

        String passwd = UaaStringUtils.nonNull(
            service!=null ? service.getPasswd() : null,
            globalLinks.getSelfService().getPasswd(),
            defaultPasswd);


        if (selfServiceLinksEnabled && !disableInternalUserManagement) {
            if (hasText(signup)) {
                signup = UaaStringUtils.replaceZoneVariables(signup, IdentityZoneHolder.get());
                selfServiceLinks.put(CREATE_ACCOUNT_LINK, signup);
                selfServiceLinks.put("register", signup);
            }
            if (hasText(passwd)) {
                passwd = UaaStringUtils.replaceZoneVariables(passwd, IdentityZoneHolder.get());
                selfServiceLinks.put(FORGOT_PASSWORD_LINK, passwd);
                selfServiceLinks.put("passwd", passwd);
            }
        }
        return selfServiceLinks;
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
            query = query == null ? "" : "?" + URLDecoder.decode(query, UTF_8.name());
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

    public void setClientDetailsService(ClientServicesExtension clientDetailsService) {
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
