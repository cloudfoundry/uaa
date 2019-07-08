package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.MfaChecker;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.SamlRedirectUtils;
import org.cloudfoundry.identity.uaa.util.*;
import org.cloudfoundry.identity.uaa.util.JsonUtils.JsonUtilException;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.*;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.bind.annotation.*;

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
import java.security.Principal;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.List;
import java.util.*;
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
 */
@Controller
public class LoginInfoEndpoint {

    private static final String MFA_CODE = "mfaCode";
    private static final Logger logger = LoggerFactory.getLogger(LoginInfoEndpoint.class);

    private static final String CREATE_ACCOUNT_LINK = "createAccountLink";
    private static final String FORGOT_PASSWORD_LINK = "forgotPasswordLink";
    private static final String LINK_CREATE_ACCOUNT_SHOW = "linkCreateAccountShow";
    private static final String FIELD_USERNAME_SHOW = "fieldUsernameShow";

    private static final List<String> UI_ONLY_ATTRIBUTES =
            Collections.unmodifiableList(
                    Arrays.asList(CREATE_ACCOUNT_LINK, FORGOT_PASSWORD_LINK, LINK_CREATE_ACCOUNT_SHOW, FIELD_USERNAME_SHOW)
            );
    private static final String PASSCODE = "passcode";
    private static final String SHOW_LOGIN_LINKS = "showLoginLinks";
    private static final String LINKS = "links";
    private static final String ZONE_NAME = "zone_name";
    private static final String ENTITY_ID = "entityID";
    private static final String IDP_DEFINITIONS = "idpDefinitions";
    private static final String OAUTH_LINKS = "oauthLinks";

    private final AuthenticationManager authenticationManager;
    private final String baseUrl;
    private final String entityID;
    private final SamlIdentityProviderConfigurator idpDefinitions;
    private final MultitenantClientServices clientDetailsService;
    private final ExpiringCodeStore expiringCodeStore;
    private final String externalLoginUrl;
    private final IdentityProviderProvisioning providerProvisioning;
    private final XOAuthProviderConfigurator xoAuthProviderConfigurator;
    private final Links globalLinks;
    private final MfaChecker mfaChecker;
    private final IdentityZoneManager identityZoneManager;
    private final Properties gitProperties;
    private final Properties buildProperties;
    private final Duration codeExpiration;
    private final MapCollector<IdentityProvider, String, AbstractXOAuthIdentityProviderDefinition> idpsMapCollector;

    LoginInfoEndpoint(
            @Qualifier("zoneAwareAuthzAuthenticationManager") final AuthenticationManager authenticationManager,
            @Qualifier("uaaUrl") final String baseUrl,
            @Qualifier("samlEntityID") final String entityID,
            final SamlIdentityProviderConfigurator idpDefinitions,
            final MultitenantClientServices clientDetailsService,
            final ExpiringCodeStore expiringCodeStore,
            @Value("${login.url:''}") final String externalLoginUrl,
            @Qualifier("identityProviderProvisioning") final IdentityProviderProvisioning providerProvisioning,
            final XOAuthProviderConfigurator xoAuthProviderConfigurator,
            final Links globalLinks,
            final MfaChecker mfaChecker,
            final IdentityZoneManager identityZoneManager
    ) {
        this.authenticationManager = authenticationManager;
        this.baseUrl = baseUrl;
        this.entityID = entityID;
        this.idpDefinitions = idpDefinitions;
        this.clientDetailsService = clientDetailsService;
        this.expiringCodeStore = expiringCodeStore;
        this.externalLoginUrl = externalLoginUrl;
        this.providerProvisioning = providerProvisioning;
        this.xoAuthProviderConfigurator = xoAuthProviderConfigurator;
        this.globalLinks = globalLinks;
        this.mfaChecker = mfaChecker;
        this.identityZoneManager = identityZoneManager;
        this.gitProperties = tryLoadProperties("git.properties");
        this.buildProperties = tryLoadProperties("build.properties");
        try {
            new URI(baseUrl);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Could not extract host from URI: " + baseUrl);
        }
        this.codeExpiration = Duration.ofMinutes(5);
        this.idpsMapCollector =
                new MapCollector<>(
                        IdentityProvider::getOriginKey,
                        idp -> (AbstractXOAuthIdentityProviderDefinition) idp.getConfig()
                );
    }

    private Properties tryLoadProperties(final String fileName) {
        try {
            return PropertiesLoaderUtils.loadAllProperties(fileName);
        } catch (IOException e) {
            return new Properties();
        }
    }

    @RequestMapping(value = {"/login"}, headers = "Accept=application/json")
    public String infoForLoginJson(Model model, Principal principal, HttpServletRequest request) {
        return login(model, principal, Collections.emptyList(), true, request);
    }

    @RequestMapping(value = {"/info"}, headers = "Accept=application/json")
    public String infoForJson(Model model, Principal principal, HttpServletRequest request) {
        return login(model, principal, Collections.emptyList(), true, request);
    }

    static class SavedAccountOptionModel extends SavedAccountOption {
        /**
         * For some unknown reason this must be public
         */
        public int red, green, blue;

        void assignColors(Color color) {
            red = color.getRed();
            blue = color.getBlue();
            green = color.getGreen();
        }
    }

    @RequestMapping(value = {"/login"}, headers = "Accept=text/html, */*")
    public String loginForHtml(Model model,
                               Principal principal,
                               HttpServletRequest request,
                               @RequestHeader(value = "Accept", required = false) List<MediaType> headers)
            throws HttpMediaTypeNotAcceptableException {

        boolean match =
                headers == null || headers.stream().anyMatch(mediaType -> mediaType.isCompatibleWith(MediaType.TEXT_HTML));
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

        return login(model, principal, Arrays.asList(PASSCODE, MFA_CODE), false, request);
    }

    private static <T extends SavedAccountOption> List<T> getSavedAccounts(Cookie[] cookies, Class<T> clazz) {
        return Arrays.asList(ofNullable(cookies).orElse(new Cookie[]{}))
                .stream()
                .filter(c -> c.getName().startsWith("Saved-Account"))
                .map(c -> {
                    try {
                        return JsonUtils.readValue(decodeCookieValue(c.getValue()), clazz);
                    } catch (JsonUtilException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private static String decodeCookieValue(String inValue) {
        String out;
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

    String getZonifiedEntityId() {
        return SamlRedirectUtils.getZonifiedEntityId(entityID, IdentityZoneHolder.get());
    }

    private String login(Model model, Principal principal, List<String> excludedPrompts, boolean jsonResponse, HttpServletRequest request) {
        if (principal instanceof UaaAuthentication && ((UaaAuthentication) principal).isAuthenticated()) {
            return "redirect:/home";
        }

        HttpSession session = request != null ? request.getSession(false) : null;
        List<String> allowedIdentityProviderKeys = null;
        String clientName = null;
        Map<String, Object> clientInfo = getClientInfo(session);
        if (clientInfo != null) {
            allowedIdentityProviderKeys = (List<String>) clientInfo.get(ClientConstants.ALLOWED_PROVIDERS);
            clientName = (String) clientInfo.get(ClientConstants.CLIENT_NAME);
        }

        Map<String, SamlIdentityProviderDefinition> samlIdentityProviders =
                getSamlIdentityProviderDefinitions(allowedIdentityProviderKeys);
        Map<String, AbstractXOAuthIdentityProviderDefinition> oauthIdentityProviders =
                getOauthIdentityProviderDefinitions(allowedIdentityProviderKeys);
        Map<String, AbstractIdentityProviderDefinition> allIdentityProviders =
                new HashMap<String, AbstractIdentityProviderDefinition>() {{
                    putAll(samlIdentityProviders);
                    putAll(oauthIdentityProviders);
                }};

        boolean fieldUsernameShow = true;
        boolean returnLoginPrompts = true;
        IdentityProvider ldapIdentityProvider = null;
        try {
            ldapIdentityProvider = providerProvisioning.retrieveByOrigin(
                    OriginKeys.LDAP, IdentityZoneHolder.get().getId()
            );
        } catch (EmptyResultDataAccessException e) {
        }
        IdentityProvider uaaIdentityProvider =
                providerProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
        // ldap and uaa disabled removes username/password input boxes
        if (!uaaIdentityProvider.isActive()) {
            if (ldapIdentityProvider == null || !ldapIdentityProvider.isActive()) {
                fieldUsernameShow = false;
                returnLoginPrompts = false;
            }
        }

        // ldap or uaa not part of allowedIdentityProviderKeys
        if (allowedIdentityProviderKeys != null &&
                !allowedIdentityProviderKeys.contains(OriginKeys.LDAP) &&
                !allowedIdentityProviderKeys.contains(OriginKeys.UAA) &&
                !allowedIdentityProviderKeys.contains(OriginKeys.KEYSTONE)) {
            fieldUsernameShow = false;
        }

        Map.Entry<String, AbstractIdentityProviderDefinition> idpForRedirect = null;
        idpForRedirect = evaluateLoginHint(model, session, samlIdentityProviders,
                oauthIdentityProviders, allIdentityProviders, allowedIdentityProviderKeys, request);

        boolean discoveryEnabled = identityZoneManager.getCurrentIdentityZone().getConfig().isIdpDiscoveryEnabled();
        boolean discoveryPerformed = Boolean.parseBoolean(request.getParameter("discoveryPerformed"));
        String defaultIdentityProviderName = identityZoneManager.getCurrentIdentityZone().getConfig().getDefaultIdentityProvider();

        idpForRedirect = evaluateIdpDiscovery(model, samlIdentityProviders, oauthIdentityProviders,
                allIdentityProviders, allowedIdentityProviderKeys, idpForRedirect, discoveryEnabled, discoveryPerformed, defaultIdentityProviderName);
        if (idpForRedirect == null && !jsonResponse && !fieldUsernameShow && allIdentityProviders.size() == 1) {
            idpForRedirect = allIdentityProviders.entrySet().stream().findAny().get();
        }
        if (idpForRedirect != null) {
            String externalRedirect = redirectToExternalProvider(
                    idpForRedirect.getValue(), idpForRedirect.getKey(), request
            );
            if (externalRedirect != null && !jsonResponse) {
                logger.debug("Following external redirect : " + externalRedirect);
                return externalRedirect;
            }
        }

        boolean linkCreateAccountShow = fieldUsernameShow;
        if (fieldUsernameShow && (allowedIdentityProviderKeys != null)) {
            if (!allowedIdentityProviderKeys.contains(OriginKeys.UAA)) {
                linkCreateAccountShow = false;
                model.addAttribute("login_hint", new UaaLoginHint(OriginKeys.LDAP).toString());
            } else if (!allowedIdentityProviderKeys.contains(OriginKeys.LDAP)) {
                model.addAttribute("login_hint", new UaaLoginHint(OriginKeys.UAA).toString());
            }
        }

        String zonifiedEntityID = getZonifiedEntityId();
        Map links = getLinksInfo();
        if (jsonResponse) {
            setJsonInfo(model, samlIdentityProviders, zonifiedEntityID, links);
        } else {
            updateLoginPageModel(model, request, clientName, samlIdentityProviders, oauthIdentityProviders,
                    fieldUsernameShow, linkCreateAccountShow);
        }

        model.addAttribute(LINKS, links);
        setCommitInfo(model);
        model.addAttribute(ZONE_NAME, identityZoneManager.getCurrentIdentityZone().getName());
        // Entity ID to start the discovery
        model.addAttribute(ENTITY_ID, zonifiedEntityID);

        excludedPrompts = new LinkedList<>(excludedPrompts);
        String origin = request != null ? request.getParameter("origin") : null;
        populatePrompts(model, excludedPrompts, origin, samlIdentityProviders, oauthIdentityProviders,
                returnLoginPrompts);

        if (principal == null) {
            return getUnauthenticatedRedirect(model, request, discoveryEnabled, discoveryPerformed);
        }
        return "home";
    }

    private String getUnauthenticatedRedirect(
            Model model,
            HttpServletRequest request,
            boolean discoveryEnabled,
            boolean discoveryPerformed
    ) {
        String formRedirectUri = request.getParameter(UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER);
        if (hasText(formRedirectUri)) {
            model.addAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER, formRedirectUri);
        }

        boolean accountChooserEnabled = IdentityZoneHolder.get().getConfig().isAccountChooserEnabled();
        boolean otherAccountSignIn = Boolean.parseBoolean(request.getParameter("otherAccountSignIn"));
        boolean savedAccountsEmpty = getSavedAccounts(request.getCookies(), SavedAccountOption.class).isEmpty();

        if (discoveryEnabled) {
            if (model.containsAttribute("login_hint")) {
                return goToPasswordPage(null, model);
            }
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

    private void updateLoginPageModel(
            Model model,
            HttpServletRequest request,
            String clientName,
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            Map<String, AbstractXOAuthIdentityProviderDefinition> oauthIdentityProviders,
            boolean fieldUsernameShow,
            boolean linkCreateAccountShow
    ) {
        model.addAttribute(LINK_CREATE_ACCOUNT_SHOW, linkCreateAccountShow);
        model.addAttribute(FIELD_USERNAME_SHOW, fieldUsernameShow);
        model.addAttribute(IDP_DEFINITIONS, samlIdentityProviders.values());
        Map<String, String> oauthLinks = new HashMap<>();
        ofNullable(oauthIdentityProviders).orElse(emptyMap()).entrySet().stream()
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

    private void setJsonInfo(
            Model model,
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            String zonifiedEntityID,
            Map links
    ) {
        for (String attribute : UI_ONLY_ATTRIBUTES) {
            links.remove(attribute);
        }
        Map<String, String> idpDefinitionsForJson = new HashMap<>();
        if (samlIdentityProviders != null) {
            for (SamlIdentityProviderDefinition def : samlIdentityProviders.values()) {
                String idpUrl = links.get("login") +
                        String.format("/saml/discovery?returnIDParam=idp&entityID=%s&idp=%s&isPassive=true",
                                zonifiedEntityID,
                                def.getIdpEntityAlias());
                idpDefinitionsForJson.put(def.getIdpEntityAlias(), idpUrl);
            }
            model.addAttribute(IDP_DEFINITIONS, idpDefinitionsForJson);
        }
    }

    private Map.Entry<String, AbstractIdentityProviderDefinition> evaluateIdpDiscovery(
            Model model,
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            Map<String, AbstractXOAuthIdentityProviderDefinition> oauthIdentityProviders,
            Map<String, AbstractIdentityProviderDefinition> allIdentityProviders,
            List<String> allowedIdentityProviderKeys,
            Map.Entry<String, AbstractIdentityProviderDefinition> idpForRedirect,
            boolean discoveryEnabled,
            boolean discoveryPerformed,
            String defaultIdentityProviderName
    ) {
        if (idpForRedirect == null && (discoveryPerformed || !discoveryEnabled) && defaultIdentityProviderName != null && !model.containsAttribute("login_hint")) { //Default set, no login_hint given, discovery disabled or performed
            if (!OriginKeys.UAA.equals(defaultIdentityProviderName) && !OriginKeys.LDAP.equals(defaultIdentityProviderName)) {
                if (allIdentityProviders.containsKey(defaultIdentityProviderName)) {
                    idpForRedirect =
                            allIdentityProviders.entrySet().stream().filter(entry -> defaultIdentityProviderName.equals(entry.getKey())).findAny().orElse(null);
                }
            } else if (allowedIdentityProviderKeys == null || allowedIdentityProviderKeys.contains(defaultIdentityProviderName)) {
                UaaLoginHint loginHint = new UaaLoginHint(defaultIdentityProviderName);
                model.addAttribute("login_hint", loginHint.toString());
                samlIdentityProviders.clear();
                oauthIdentityProviders.clear();
            }
        }
        return idpForRedirect;
    }

    private Map.Entry<String, AbstractIdentityProviderDefinition> evaluateLoginHint(
            Model model,
            HttpSession session,
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            Map<String, AbstractXOAuthIdentityProviderDefinition> oauthIdentityProviders,
            Map<String, AbstractIdentityProviderDefinition> allIdentityProviders,
            List<String> allowedIdentityProviderKeys,
            HttpServletRequest request
    ) {

        Map.Entry<String, AbstractIdentityProviderDefinition> idpForRedirect = null;
        String loginHintParam =
                ofNullable(session)
                        .flatMap(s -> ofNullable((SavedRequest) s.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE)))
                        .flatMap(sr -> ofNullable(sr.getParameterValues("login_hint")))
                        .flatMap(lhValues -> Arrays.asList(lhValues).stream().findFirst())
                        .orElse(request.getParameter("login_hint"));

        if (loginHintParam != null) {
            String loginHint = loginHintParam;
            // parse login_hint in JSON format
            UaaLoginHint uaaLoginHint = UaaLoginHint.parseRequestParameter(loginHint);
            if (uaaLoginHint != null) {
                logger.debug("Received login hint: " + loginHint);
                logger.debug("Received login hint with origin: " + uaaLoginHint.getOrigin());
                if (OriginKeys.UAA.equals(uaaLoginHint.getOrigin()) || OriginKeys.LDAP.equals(uaaLoginHint.getOrigin())) {
                    if (allowedIdentityProviderKeys == null || allowedIdentityProviderKeys.contains(uaaLoginHint.getOrigin())) {
                        // in case of uaa/ldap, pass value to login page
                        model.addAttribute("login_hint", loginHint);
                        samlIdentityProviders.clear();
                        oauthIdentityProviders.clear();
                    } else {
                        model.addAttribute("error", "invalid_login_hint");
                    }
                } else {
                    // for oidc/saml, trigger the redirect
                    List<Map.Entry<String, AbstractIdentityProviderDefinition>> hintIdentityProviders =
                            allIdentityProviders.entrySet().stream().filter(
                                    idp -> idp.getKey().equals(uaaLoginHint.getOrigin())
                            ).collect(Collectors.toList());
                    if (hintIdentityProviders.size() > 1) {
                        throw new IllegalStateException(
                                "There is a misconfiguration with the identity provider(s). Please contact your system administrator."
                        );
                    } else if (hintIdentityProviders.size() == 1) {
                        idpForRedirect = hintIdentityProviders.get(0);
                        logger.debug("Setting redirect from origin login_hint to: " + idpForRedirect);
                    } else {
                        logger.debug("Client does not allow provider for login_hint with origin key: "
                                + uaaLoginHint.getOrigin());
                        model.addAttribute("error", "invalid_login_hint");
                    }
                }
            } else {
                // login_hint in JSON format was not available, try old format (email domain)
                List<Map.Entry<String, AbstractIdentityProviderDefinition>> matchingIdentityProviders =
                        allIdentityProviders.entrySet().stream().filter(
                                idp -> ofNullable(idp.getValue().getEmailDomain()).orElse(Collections.emptyList()).contains(loginHint)
                        ).collect(Collectors.toList());
                if (matchingIdentityProviders.size() > 1) {
                    throw new IllegalStateException(
                            "There is a misconfiguration with the identity provider(s). Please contact your system administrator."
                    );
                } else if (matchingIdentityProviders.size() == 1) {
                    idpForRedirect = matchingIdentityProviders.get(0);
                    logger.debug("Setting redirect from email domain login hint to: " + idpForRedirect);
                }
            }
        }
        return idpForRedirect;
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
        if (idpForRedirect != null) {
            if (idpForRedirect instanceof SamlIdentityProviderDefinition) {
                String url = SamlRedirectUtils.getIdpRedirectUrl((SamlIdentityProviderDefinition) idpForRedirect, entityID, IdentityZoneHolder.get());
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

    private Map<String, SamlIdentityProviderDefinition> getSamlIdentityProviderDefinitions(List<String> allowedIdps) {
        List<SamlIdentityProviderDefinition> filteredIdps = idpDefinitions.getIdentityProviderDefinitions(allowedIdps, identityZoneManager.getCurrentIdentityZone());
        return filteredIdps.stream().collect(new MapCollector<>(SamlIdentityProviderDefinition::getIdpEntityAlias, idp -> idp));
    }

    Map<String, AbstractXOAuthIdentityProviderDefinition> getOauthIdentityProviderDefinitions(List<String> allowedIdps) {

        List<IdentityProvider> identityProviders =
                xoAuthProviderConfigurator.retrieveAll(true, identityZoneManager.getCurrentIdentityZoneId());

        Map<String, AbstractXOAuthIdentityProviderDefinition> identityProviderDefinitions = identityProviders.stream()
                .filter(p -> allowedIdps == null || allowedIdps.contains(p.getOriginKey()))
                .collect(idpsMapCollector);
        return identityProviderDefinitions;
    }

    private boolean hasSavedOauthAuthorizeRequest(HttpSession session) {
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

    private Map<String, Object> getClientInfo(HttpSession session) {
        if (!hasSavedOauthAuthorizeRequest(session)) {
            return null;
        }
        SavedRequest savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        String[] client_ids = savedRequest.getParameterValues("client_id");
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(client_ids[0], identityZoneManager.getCurrentIdentityZoneId());
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


    private void populatePrompts(
            Model model,
            List<String> promptsToExclude,
            String origin,
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            Map<String, AbstractXOAuthIdentityProviderDefinition> oauthIdentityProviders,
            boolean returnLoginPrompts
    ) {
        boolean noIdpsPresent = true;
        for (SamlIdentityProviderDefinition idp : samlIdentityProviders.values()) {
            if (idp.isShowSamlLink()) {
                model.addAttribute(SHOW_LOGIN_LINKS, true);
                noIdpsPresent = false;
                break;
            }
        }
        for (AbstractXOAuthIdentityProviderDefinition oauthIdp : oauthIdentityProviders.values()) {
            if (oauthIdp.isShowLinkText()) {
                model.addAttribute(SHOW_LOGIN_LINKS, true);
                noIdpsPresent = false;
                break;
            }
        }
        //make the list writeable
        if (noIdpsPresent) {
            promptsToExclude.add(PASSCODE);
        }
        if (!returnLoginPrompts) {
            promptsToExclude.add("username");
            promptsToExclude.add("password");
        }

        List<Prompt> prompts;
        IdentityZoneConfiguration zoneConfiguration = identityZoneManager.getCurrentIdentityZone().getConfig();
        if (isNull(zoneConfiguration)) {
            zoneConfiguration = new IdentityZoneConfiguration();
        }
        prompts = zoneConfiguration.getPrompts();
        if (origin != null) {
            IdentityProvider providerForOrigin = null;
            try {
                providerForOrigin = providerProvisioning.retrieveByOrigin(origin, identityZoneManager.getCurrentIdentityZoneId());
            } catch (DataAccessException e) {
            }
            if (providerForOrigin != null) {
                if (providerForOrigin.getConfig() instanceof OIDCIdentityProviderDefinition) {
                    OIDCIdentityProviderDefinition oidcConfig = (OIDCIdentityProviderDefinition) providerForOrigin.getConfig();
                    List<Prompt> providerPrompts = oidcConfig.getPrompts();
                    if (providerPrompts != null) {
                        prompts = providerPrompts;
                    }
                }
            }
        }
        Map<String, String[]> map = new LinkedHashMap<>();
        for (Prompt prompt : prompts) {
            String[] details = prompt.getDetails();
            if (PASSCODE.equals(prompt.getName()) && !identityZoneManager.isCurrentZoneUaa()) {
                String urlInPasscode = extractUrlFromString(prompt.getDetails()[1]);
                if (hasText(urlInPasscode)) {
                    String[] newDetails = new String[details.length];
                    System.arraycopy(details, 0, newDetails, 0, details.length);
                    newDetails[1] = newDetails[1].replace(urlInPasscode, addSubdomainToUrl(urlInPasscode, identityZoneManager.getCurrentIdentityZone().getSubdomain()));
                    details = newDetails;
                }
            }
            map.put(prompt.getName(), details);
        }
        if (mfaChecker.isMfaEnabled(identityZoneManager.getCurrentIdentityZone())) {
            Prompt p = new Prompt(
                    MFA_CODE,
                    "password",
                    "MFA Code ( Register at " + addSubdomainToUrl(baseUrl + " )", identityZoneManager.getCurrentIdentityZone().getSubdomain())
            );
            map.putIfAbsent(p.getName(), p.getDetails());
        }
        for (String excludeThisPrompt : promptsToExclude) {
            map.remove(excludeThisPrompt);
        }
        model.addAttribute("prompts", map);
    }

    //http://stackoverflow.com/questions/5713558/detect-and-extract-url-from-a-string
    // Pattern for recognizing a URL, based off RFC 3986
    private static final Pattern urlPattern = Pattern.compile(
            "((https?|ftp|gopher|telnet|file):((//)|(\\\\))+[\\w\\d:#@%/;$()~_?\\+-=\\\\\\.&]*)",
            Pattern.CASE_INSENSITIVE);

    private String extractUrlFromString(String s) {
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
    public String discoverIdentityProvider(@RequestParam String email, @RequestParam(required = false) String skipDiscovery, @RequestParam(required = false, name = "login_hint") String loginHint, Model model, HttpSession session, HttpServletRequest request) {
        ClientDetails clientDetails = null;
        if (hasSavedOauthAuthorizeRequest(session)) {
            SavedRequest savedRequest = (SavedRequest) session.getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
            String[] client_ids = savedRequest.getParameterValues("client_id");
            try {
                clientDetails = clientDetailsService.loadClientByClientId(client_ids[0], IdentityZoneHolder.get().getId());
            } catch (NoSuchClientException e) {
            }
        }
        if (StringUtils.hasText(loginHint)) {
            model.addAttribute("login_hint", loginHint);
        }
        List<IdentityProvider> identityProviders = DomainFilter.filter(providerProvisioning.retrieveActive(IdentityZoneHolder.get().getId()), clientDetails, email, false);

        if (!StringUtils.hasText(skipDiscovery) && identityProviders.size() == 1) {
            IdentityProvider matchedIdp = identityProviders.get(0);
            if (matchedIdp.getType().equals(UAA)) {
                model.addAttribute("login_hint", new UaaLoginHint(OriginKeys.UAA).toString());
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
        if (mfaChecker.isMfaEnabled(IdentityZoneHolder.get())) {
            throw new BadCredentialsException("MFA is required");
        }

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
        if (userAuthentication != null && userAuthentication.getPrincipal() instanceof UaaPrincipal) {
            UaaPrincipal p = (UaaPrincipal) userAuthentication.getPrincipal();
            if (p != null) {
                codeData.put("user_id", p.getId());
                codeData.put(OriginKeys.ORIGIN, p.getOrigin());
            }
        }
        ExpiringCode expiringCode = expiringCodeStore.generateCode(
                JsonUtils.writeValueAsString(codeData),
                new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000),
                ExpiringCodeType.AUTOLOGIN.name(),
                IdentityZoneHolder.get().getId());

        return new AutologinResponse(expiringCode.getCode());
    }

    @RequestMapping(value = "/autologin", method = GET)
    public String performAutologin(HttpSession session) {
        if (mfaChecker.isMfaEnabled(IdentityZoneHolder.get())) {
            throw new BadCredentialsException("MFA is required");
        }
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

    @RequestMapping(value = {"/passcode"}, method = GET)
    public String generatePasscode(Map<String, Object> model, Principal principal) {
        String username;
        String origin;
        String userId;
        Map<String, Object> authorizationParameters = null;

        if (principal instanceof UaaPrincipal) {
            UaaPrincipal uaaPrincipal = (UaaPrincipal) principal;
            username = uaaPrincipal.getName();
            origin = uaaPrincipal.getOrigin();
            userId = uaaPrincipal.getId();
        } else if (principal instanceof UaaAuthentication) {
            UaaPrincipal uaaPrincipal = ((UaaAuthentication) principal).getPrincipal();
            username = uaaPrincipal.getName();
            origin = uaaPrincipal.getOrigin();
            userId = uaaPrincipal.getId();
        } else if (principal instanceof LoginSamlAuthenticationToken) {
            username = principal.getName();
            origin = ((LoginSamlAuthenticationToken) principal).getUaaPrincipal().getOrigin();
            userId = ((LoginSamlAuthenticationToken) principal).getUaaPrincipal().getId();
        } else if (principal instanceof Authentication && ((Authentication) principal).getPrincipal() instanceof UaaPrincipal) {
            UaaPrincipal uaaPrincipal = (UaaPrincipal) ((Authentication) principal).getPrincipal();
            username = uaaPrincipal.getName();
            origin = uaaPrincipal.getOrigin();
            userId = uaaPrincipal.getId();
        } else {
            throw new UnknownPrincipalException();
        }

        PasscodeInformation pi = new PasscodeInformation(userId, username, null, origin, authorizationParameters);

        String intent = ExpiringCodeType.PASSCODE + " " + pi.getUserId();

        expiringCodeStore.expireByIntent(intent, identityZoneManager.getCurrentIdentityZoneId());

        ExpiringCode code = expiringCodeStore.generateCode(
                JsonUtils.writeValueAsString(pi),
                new Timestamp(System.currentTimeMillis() + codeExpiration.toMillis()),
                intent, identityZoneManager.getCurrentIdentityZoneId());

        model.put(PASSCODE, code.getCode());

        return PASSCODE;
    }

    private Map<String, ?> getLinksInfo() {

        Map<String, Object> model = new HashMap<>();
        model.put(OriginKeys.UAA, addSubdomainToUrl(baseUrl, identityZoneManager.getCurrentIdentityZone().getSubdomain()));
        if (baseUrl.contains("localhost:")) {
            model.put("login", addSubdomainToUrl(baseUrl, identityZoneManager.getCurrentIdentityZone().getSubdomain()));
        } else if (hasText(externalLoginUrl)) {
            model.put("login", externalLoginUrl);
        } else {
            model.put("login", addSubdomainToUrl(baseUrl.replaceAll(OriginKeys.UAA, "login"), identityZoneManager.getCurrentIdentityZone().getSubdomain()));
        }
        model.putAll(getSelfServiceLinks());
        return model;
    }

    Map<String, String> getSelfServiceLinks() {
        Map<String, String> selfServiceLinks = new HashMap<>();
        IdentityZone zone = identityZoneManager.getCurrentIdentityZone();
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = providerProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
        boolean disableInternalUserManagement = (uaaIdp.getConfig() != null) ? uaaIdp.getConfig().isDisableInternalUserManagement() : false;

        boolean selfServiceLinksEnabled = (zone.getConfig() != null) ? zone.getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled() : true;

        final String defaultSignup = "/create_account";
        final String defaultPasswd = "/forgot_password";
        Links.SelfService service = zone.getConfig() != null ? zone.getConfig().getLinks().getSelfService() : null;
        String signup = UaaStringUtils.nonNull(
                service != null ? service.getSignup() : null,
                globalLinks.getSelfService().getSignup(),
                defaultSignup);

        String passwd = UaaStringUtils.nonNull(
                service != null ? service.getPasswd() : null,
                globalLinks.getSelfService().getPasswd(),
                defaultPasswd);


        if (selfServiceLinksEnabled && !disableInternalUserManagement) {
            if (hasText(signup)) {
                signup = UaaStringUtils.replaceZoneVariables(signup, zone);
                selfServiceLinks.put(CREATE_ACCOUNT_LINK, signup);
                selfServiceLinks.put("register", signup);
            }
            if (hasText(passwd)) {
                passwd = UaaStringUtils.replaceZoneVariables(passwd, zone);
                selfServiceLinks.put(FORGOT_PASSWORD_LINK, passwd);
                selfServiceLinks.put("passwd", passwd);
            }
        }
        return selfServiceLinks;
    }

    @ResponseStatus(value = HttpStatus.FORBIDDEN, reason = "Unknown authentication token type, unable to derive user ID.")
    static final class UnknownPrincipalException extends RuntimeException {
    }

}