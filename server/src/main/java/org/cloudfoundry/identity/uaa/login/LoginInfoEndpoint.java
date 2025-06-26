package org.cloudfoundry.identity.uaa.login;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.SamlRedirectUtils;
import org.cloudfoundry.identity.uaa.util.ColorHash;
import org.cloudfoundry.identity.uaa.util.DomainFilter;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils.JsonUtilException;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.awt.*;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.Principal;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getDecoder;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Objects.isNull;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;
import static org.springframework.util.StringUtils.hasText;

/**
 * Controller that sends login info (e.g. prompts) to clients wishing to
 * authenticate.
 */
@Controller
@Slf4j
public class LoginInfoEndpoint {

    private static final String CREATE_ACCOUNT_LINK = "createAccountLink";
    private static final String FORGOT_PASSWORD_LINK = "forgotPasswordLink";
    private static final String LINK_CREATE_ACCOUNT_SHOW = "linkCreateAccountShow";
    private static final String FIELD_USERNAME_SHOW = "fieldUsernameShow";

    private static final List<String> UI_ONLY_ATTRIBUTES = List.of(CREATE_ACCOUNT_LINK, FORGOT_PASSWORD_LINK, LINK_CREATE_ACCOUNT_SHOW, FIELD_USERNAME_SHOW);
    private static final String PASSCODE = "passcode";
    private static final String SHOW_LOGIN_LINKS = "showLoginLinks";
    private static final String LINKS = "links";
    private static final String ZONE_NAME = "zone_name";
    private static final String ENTITY_ID = "entityID";
    private static final String IDP_DEFINITIONS = "idpDefinitions";
    private static final String OAUTH_LINKS = "oauthLinks";
    private static final String LOGIN_HINT_ATTRIBUTE = "login_hint";
    private static final String EMAIL_ATTRIBUTE = "email";
    private static final String ERROR_ATTRIBUTE = "error";
    private static final String USERNAME_PARAMETER = "username";
    private static final String CLIENT_ID_PARAMETER = "client_id";
    private static final String LOGIN = "login";
    private static final String REDIRECT = "redirect:";
    private static final MapCollector<IdentityProvider, String, AbstractExternalOAuthIdentityProviderDefinition> idpsMapCollector =
            new MapCollector<>(
                    IdentityProvider::getOriginKey,
                    idp -> (AbstractExternalOAuthIdentityProviderDefinition) idp.getConfig()
            );
    //http://stackoverflow.com/questions/5713558/detect-and-extract-url-from-a-string
    // Pattern for recognizing a URL, based off RFC 3986
    private static final Pattern urlPattern = Pattern.compile(
            "((https?|ftp|gopher|telnet|file):((//)|(\\\\))+[\\w\\d:#@%/;$()~_?\\+-=\\\\\\.&]*)",
            Pattern.CASE_INSENSITIVE);
    private final Properties gitProperties;
    private final Properties buildProperties;
    private final String baseUrl;
    private final String externalLoginUrl;
    private final SamlIdentityProviderConfigurator idpDefinitions;
    private final AuthenticationManager authenticationManager;
    private final ExpiringCodeStore expiringCodeStore;
    private final MultitenantClientServices clientDetailsService;
    private final IdentityProviderProvisioning providerProvisioning;
    private final ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator;
    private final Links globalLinks;
    private final String entityID;

    public LoginInfoEndpoint(
            final @Qualifier("zoneAwareAuthzAuthenticationManager") AuthenticationManager authenticationManager,
            final @Qualifier("codeStore") ExpiringCodeStore expiringCodeStore,
            final @Value("${login.url:''}") String externalLoginUrl,
            final @Qualifier("uaaUrl") String baseUrl,
            final @Qualifier("externalOAuthProviderConfigurator") ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator,
            final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning providerProvisioning,
            final @Qualifier("samlEntityID") String entityID,
            final @Qualifier("globalLinks") Links globalLinks,
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            final @Qualifier("metaDataProviders") SamlIdentityProviderConfigurator idpDefinitions) {
        this.authenticationManager = authenticationManager;
        this.expiringCodeStore = expiringCodeStore;
        this.externalLoginUrl = externalLoginUrl;
        this.baseUrl = baseUrl;
        this.externalOAuthProviderConfigurator = externalOAuthProviderConfigurator;
        this.providerProvisioning = providerProvisioning;
        this.entityID = entityID;
        this.globalLinks = globalLinks;
        this.clientDetailsService = clientDetailsService;
        this.idpDefinitions = idpDefinitions;
        gitProperties = tryLoadAllProperties("git.properties");
        buildProperties = tryLoadAllProperties("build.properties");
    }

    private static Properties tryLoadAllProperties(final String fileName) {
        try {
            return PropertiesLoaderUtils.loadAllProperties(fileName);
        } catch (IOException ignored) {
            return new Properties();
        }
    }

    private static <T extends SavedAccountOption> List<T> getSavedAccounts(Cookie[] cookies, Class<T> clazz) {
        return Arrays.stream(ofNullable(cookies).orElse(new Cookie[]{}))
                .filter(c -> c.getName().startsWith("Saved-Account"))
                .map(c -> {
                    try {
                        return JsonUtils.readValue(decodeCookieValue(c.getValue()), clazz);
                    } catch (JsonUtilException e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();
    }

    private static String decodeCookieValue(String inValue) {
        try {
            return URLDecoder.decode(inValue, UTF_8);
        } catch (Exception e) {
            log.debug("URLDecoder.decode failed for {}", inValue, e);
            return "";
        }
    }

    private static Map<String, AbstractIdentityProviderDefinition> concatenateMaps(Map<String, SamlIdentityProviderDefinition> samlIdentityProviders, Map<String, ? extends AbstractExternalOAuthIdentityProviderDefinition> oauthIdentityProviders) {
        Map<String, AbstractIdentityProviderDefinition> allIdentityProviders = new HashMap<>(samlIdentityProviders);
        allIdentityProviders.putAll(oauthIdentityProviders);
        return allIdentityProviders;
    }

    @RequestMapping(value = {"/login"}, headers = "Accept=application/json")
    public String infoForLoginJson(Model model, Principal principal, HttpServletRequest request) {
        return login(model, principal, emptyList(), true, request);
    }

    @RequestMapping(value = {"/info"}, headers = "Accept=application/json")
    public String infoForJson(Model model, Principal principal, HttpServletRequest request) {
        return login(model, principal, emptyList(), true, request);
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

        return login(model, principal, List.of(PASSCODE), false, request);
    }

    @RequestMapping(value = {"/invalid_request"})
    public String invalidRequest() {
        return "invalid_request";
    }

    protected String getZonifiedEntityId() {
        return SamlRedirectUtils.getZonifiedEntityId(entityID, IdentityZoneHolder.get());
    }

    private String login(Model model, Principal principal, List<String> excludedPrompts, boolean jsonResponse, HttpServletRequest request) {
        if (principal instanceof UaaAuthentication uaaPrincipal && uaaPrincipal.isAuthenticated()) {
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

        //Read all configuration and parameters at the beginning to allow earlier decisions
        boolean discoveryEnabled = IdentityZoneHolder.get().getConfig().isIdpDiscoveryEnabled();
        boolean discoveryPerformed = Boolean.parseBoolean(request.getParameter("discoveryPerformed"));
        String defaultIdentityProviderName = IdentityZoneHolder.get().getConfig().getDefaultIdentityProvider();
        if (defaultIdentityProviderName != null) {
            model.addAttribute("defaultIdpName", defaultIdentityProviderName);
        }
        boolean accountChooserEnabled = IdentityZoneHolder.get().getConfig().isAccountChooserEnabled();
        boolean otherAccountSignIn = Boolean.parseBoolean(request.getParameter("otherAccountSignIn"));
        boolean savedAccountsEmpty = getSavedAccounts(request.getCookies(), SavedAccountOption.class).isEmpty();
        boolean accountChooserNeeded = accountChooserEnabled
                && !(otherAccountSignIn || savedAccountsEmpty)
                && !discoveryPerformed;
        boolean newLoginPageEnabled = accountChooserEnabled || discoveryEnabled;


        String loginHintParam = extractLoginHintParam(session, request);
        UaaLoginHint uaaLoginHint = UaaLoginHint.parseRequestParameter(loginHintParam);

        Map<String, SamlIdentityProviderDefinition> samlIdentityProviders = null;
        Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdentityProviders = null;
        Map<String, AbstractIdentityProviderDefinition> allIdentityProviders = Map.of();
        Map.Entry<String, AbstractIdentityProviderDefinition> loginHintProvider = null;

        if (uaaLoginHint != null && (allowedIdentityProviderKeys == null || allowedIdentityProviderKeys.contains(uaaLoginHint.getOrigin()))) {
            // Login hint: Only try to read the hinted IdP from the database
            if (!(OriginKeys.UAA.equals(uaaLoginHint.getOrigin()) || OriginKeys.LDAP.equals(uaaLoginHint.getOrigin()))) {
                try {
                    final IdentityProvider idp = externalOAuthProviderConfigurator.retrieveByOrigin(
                            uaaLoginHint.getOrigin(),
                            IdentityZoneHolder.get().getId()
                    );
                    if (idp != null) {
                        loginHintProvider = Map.entry(idp.getOriginKey(), idp.getConfig());
                        if (idp.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition oAuthConfig) {
                            oauthIdentityProviders = new HashMap<>();
                            oauthIdentityProviders.put(idp.getOriginKey(), oAuthConfig);
                        } else if (idp.getConfig() instanceof SamlIdentityProviderDefinition samlConfig) {
                            samlIdentityProviders = new HashMap<>();
                            samlIdentityProviders.put(idp.getOriginKey(), samlConfig);
                        }
                    }
                } catch (EmptyResultDataAccessException ignored) {
                    // ignore
                }
            }
            if (loginHintProvider != null) {
                oauthIdentityProviders = addDefaultOauthMap(oauthIdentityProviders, allowedIdentityProviderKeys, defaultIdentityProviderName);
                samlIdentityProviders = addDefaultSamlMap(samlIdentityProviders, allowedIdentityProviderKeys, defaultIdentityProviderName);
            } else {
                accountChooserNeeded = false;
                samlIdentityProviders = getSamlIdentityProviderDefinitions(allowedIdentityProviderKeys);
                oauthIdentityProviders = getOauthIdentityProviderDefinitions(allowedIdentityProviderKeys);
                allIdentityProviders = concatenateMaps(samlIdentityProviders, oauthIdentityProviders);
            }
        } else if (!jsonResponse && (accountChooserNeeded || (accountChooserEnabled && !discoveryEnabled && !discoveryPerformed))) {
            // when `/login` is requested to return html response (as opposed to json response)
            //Account and origin chooser do not need idp information
            oauthIdentityProviders = addDefaultOauthMap(oauthIdentityProviders, allowedIdentityProviderKeys, defaultIdentityProviderName);
            samlIdentityProviders = addDefaultSamlMap(samlIdentityProviders, allowedIdentityProviderKeys, defaultIdentityProviderName);
        } else {
            samlIdentityProviders = getSamlIdentityProviderDefinitions(allowedIdentityProviderKeys);

            if (jsonResponse) {
                /* the OAuth IdPs and all IdPs are used for determining the redirect; if jsonResponse is true, the
                 * redirect is ignored anyway */
                oauthIdentityProviders = addDefaultOauthMap(oauthIdentityProviders, allowedIdentityProviderKeys, defaultIdentityProviderName);
            } else {
                oauthIdentityProviders = getOauthIdentityProviderDefinitions(allowedIdentityProviderKeys);
            }

            allIdentityProviders = concatenateMaps(samlIdentityProviders, oauthIdentityProviders);
        }

        boolean fieldUsernameShow = true;
        boolean returnLoginPrompts = true;
        IdentityProvider ldapIdentityProvider = null;
        try {
            ldapIdentityProvider = providerProvisioning.retrieveByOrigin(
                    OriginKeys.LDAP, IdentityZoneHolder.get().getId()
            );
        } catch (EmptyResultDataAccessException ignored) {
            // ignore
        }
        IdentityProvider uaaIdentityProvider =
                providerProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        // ldap and uaa disabled removes username/password input boxes
        if (!uaaIdentityProvider.isActive() && (ldapIdentityProvider == null || !ldapIdentityProvider.isActive())) {
            fieldUsernameShow = false;
            returnLoginPrompts = false;
        }

        // ldap or uaa not part of allowedIdentityProviderKeys
        if (allowedIdentityProviderKeys != null &&
                !allowedIdentityProviderKeys.contains(OriginKeys.LDAP) &&
                !allowedIdentityProviderKeys.contains(OriginKeys.UAA) &&
                !allowedIdentityProviderKeys.contains(OriginKeys.KEYSTONE)) {
            fieldUsernameShow = false;
        }

        // redirect to external IdP, if necessary
        Map.Entry<String, AbstractIdentityProviderDefinition> idpForRedirect = evaluateLoginHint(model, samlIdentityProviders,
                oauthIdentityProviders, allIdentityProviders, allowedIdentityProviderKeys, loginHintParam, uaaLoginHint, loginHintProvider);
        if (idpForRedirect == null) {
            idpForRedirect = evaluateIdpDiscovery(model, samlIdentityProviders, oauthIdentityProviders,
                    allIdentityProviders, allowedIdentityProviderKeys, discoveryPerformed, newLoginPageEnabled, defaultIdentityProviderName);
        }
        if (idpForRedirect == null && !jsonResponse && !fieldUsernameShow && allIdentityProviders.size() == 1) {
            idpForRedirect = allIdentityProviders.entrySet().stream().findFirst().orElse(null);
        }
        if (idpForRedirect != null && !jsonResponse) {
            String externalRedirect = redirectToExternalProvider(
                    idpForRedirect.getValue(), idpForRedirect.getKey(), request
            );
            if (externalRedirect != null) {
                log.debug("Following external redirect : {}", externalRedirect);
                return externalRedirect;
            }
        }

        boolean linkCreateAccountShow = fieldUsernameShow;
        if (fieldUsernameShow && (allowedIdentityProviderKeys != null) && ((!discoveryEnabled && !accountChooserEnabled) || discoveryPerformed)) {
            if (!allowedIdentityProviderKeys.contains(OriginKeys.UAA)) {
                linkCreateAccountShow = false;
                model.addAttribute(LOGIN_HINT_ATTRIBUTE, new UaaLoginHint(OriginKeys.LDAP).toString());
            } else if (!allowedIdentityProviderKeys.contains(OriginKeys.LDAP)) {
                model.addAttribute(LOGIN_HINT_ATTRIBUTE, new UaaLoginHint(OriginKeys.UAA).toString());
            }
        }

        String zonifiedEntityID = getZonifiedEntityId();
        Map<String, ?> links = getLinksInfo();
        if (jsonResponse) {
            setJsonInfo(model, samlIdentityProviders, links);
        } else {
            updateLoginPageModel(model, request, clientName, samlIdentityProviders, oauthIdentityProviders,
                    fieldUsernameShow, linkCreateAccountShow);
        }

        model.addAttribute(LINKS, links);
        setCommitInfo(model);
        model.addAttribute(ZONE_NAME, IdentityZoneHolder.get().getName());
        // Entity ID to start the discovery
        model.addAttribute(ENTITY_ID, zonifiedEntityID);

        String origin = request.getParameter("origin");
        populatePrompts(model, excludedPrompts, origin, samlIdentityProviders, oauthIdentityProviders, returnLoginPrompts);

        if (principal == null) {
            return getUnauthenticatedRedirect(model, request, discoveryEnabled, discoveryPerformed, accountChooserNeeded, accountChooserEnabled);
        }
        return "home";
    }

    private String getUnauthenticatedRedirect(
            Model model,
            HttpServletRequest request,
            boolean discoveryEnabled,
            boolean discoveryPerformed,
            boolean accountChooserNeeded,
            boolean accountChooserEnabled
    ) {
        String formRedirectUri = request.getParameter(UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER);
        if (hasText(formRedirectUri)) {
            model.addAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER, formRedirectUri);
        }
        if (accountChooserNeeded) {
            return "idp_discovery/account_chooser";
        }
        if (discoveryEnabled) {
            if (!discoveryPerformed) {
                return "idp_discovery/email";
            }
            return goToPasswordPage(request.getParameter(EMAIL_ATTRIBUTE), model);
        }
        if (accountChooserEnabled) {
            if (model.containsAttribute(LOGIN_HINT_ATTRIBUTE)) {
                return goToPasswordPage(request.getParameter(EMAIL_ATTRIBUTE), model);
            }
            if (model.containsAttribute(ERROR_ATTRIBUTE)) {
                return "idp_discovery/account_chooser";
            }
            if (discoveryPerformed) {
                return goToPasswordPage(request.getParameter(EMAIL_ATTRIBUTE), model);
            }
            return "idp_discovery/origin";
        }
        return LOGIN;
    }

    private void updateLoginPageModel(
            Model model,
            HttpServletRequest request,
            String clientName,
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdentityProviders,
            boolean fieldUsernameShow,
            boolean linkCreateAccountShow
    ) {
        Comparator<SamlIdentityProviderDefinition> sortingByLinkText = Comparator.comparing(SamlIdentityProviderDefinition::getLinkText, String.CASE_INSENSITIVE_ORDER);
        model.addAttribute(LINK_CREATE_ACCOUNT_SHOW, linkCreateAccountShow);
        model.addAttribute(FIELD_USERNAME_SHOW, fieldUsernameShow);
        model.addAttribute(IDP_DEFINITIONS, samlIdentityProviders.values().stream().sorted(sortingByLinkText).toList());
        Map<String, String> oauthLinks = new HashMap<>();
        ofNullable(oauthIdentityProviders).orElse(emptyMap()).entrySet().stream()
                .filter(e -> e.getValue() != null && e.getValue().isShowLinkText() && e.getKey() != null)
                .forEach(e ->
                        oauthLinks.put(
                                externalOAuthProviderConfigurator.getIdpAuthenticationUrl(
                                        e.getValue(),
                                        e.getKey(),
                                        request),
                                e.getValue().getLinkText()
                        )
                );
        model.addAttribute(OAUTH_LINKS, oauthLinks.entrySet().stream().sorted(Map.Entry.comparingByValue(String::compareToIgnoreCase)).toList());
        model.addAttribute("clientName", clientName);
    }

    private void setJsonInfo(
            Model model,
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            Map<String, ?> links
    ) {
        for (String attribute : UI_ONLY_ATTRIBUTES) {
            links.remove(attribute);
        }
        Map<String, String> idpDefinitionsForJson = new HashMap<>();
        if (samlIdentityProviders != null) {
            for (SamlIdentityProviderDefinition def : samlIdentityProviders.values()) {
                String idpUrl = "%s/saml2/authenticate/%s".formatted(links.get(LOGIN), def.getIdpEntityAlias());
                idpDefinitionsForJson.put(def.getIdpEntityAlias(), idpUrl);
            }
            model.addAttribute(IDP_DEFINITIONS, idpDefinitionsForJson);
        }
    }

    private Map.Entry<String, AbstractIdentityProviderDefinition> evaluateIdpDiscovery(
            final Model model,
            final Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            final Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdentityProviders,
            final Map<String, AbstractIdentityProviderDefinition> allIdentityProviders,
            final List<String> allowedIdentityProviderKeys,
            final boolean discoveryPerformed,
            final boolean newLoginPageEnabled,
            final String defaultIdentityProviderName
    ) {
        if (model.containsAttribute(LOGIN_HINT_ATTRIBUTE) || model.containsAttribute(ERROR_ATTRIBUTE)) {
            return null;
        }

        if (defaultIdentityProviderName == null) {
            return null;
        }

        if (!discoveryPerformed && newLoginPageEnabled) {
            return null;
        }

        if (!OriginKeys.UAA.equals(defaultIdentityProviderName) && !OriginKeys.LDAP.equals(defaultIdentityProviderName)) {
            if (allIdentityProviders.containsKey(defaultIdentityProviderName)) {
                return allIdentityProviders.entrySet().stream()
                                .filter(entry -> defaultIdentityProviderName.equals(entry.getKey()))
                                .findAny()
                                .orElse(null);
            }
            return null;
        }

        if (allowedIdentityProviderKeys == null || allowedIdentityProviderKeys.contains(defaultIdentityProviderName)) {
            final UaaLoginHint loginHint = new UaaLoginHint(defaultIdentityProviderName);
            model.addAttribute(LOGIN_HINT_ATTRIBUTE, loginHint.toString());
            samlIdentityProviders.clear();
            oauthIdentityProviders.clear();
        }

        return null;
    }

    private String extractLoginHintParam(HttpSession session, HttpServletRequest request) {
        return ofNullable(session)
                .flatMap(s -> ofNullable(SessionUtils.getSavedRequestSession(s)))
                .flatMap(sr -> ofNullable(sr.getParameterValues(LOGIN_HINT_ATTRIBUTE)))
                .flatMap(lhValues -> Arrays.stream(lhValues).findFirst())
                .orElse(request.getParameter(LOGIN_HINT_ATTRIBUTE));
    }

    /**
     * @return its origin key and configuration if exactly one SAML/OAuth IdP qualifies for a redirect,
     *          {@code null} otherwise
     */
    private Map.Entry<String, AbstractIdentityProviderDefinition> evaluateLoginHint(
            final Model model,
            final Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            final Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdentityProviders,
            final Map<String, AbstractIdentityProviderDefinition> allIdentityProviders,
            final List<String> allowedIdentityProviderKeys,
            final String loginHintParam,
            final UaaLoginHint uaaLoginHint,
            final Map.Entry<String, AbstractIdentityProviderDefinition> loginHintProvider
    ) {
        if (loginHintParam == null) {
            return null;
        }

        // login hint was provided, but could not be parsed into JSON format -> try old format (email domain)
        if (uaaLoginHint == null) {
            final List<Map.Entry<String, AbstractIdentityProviderDefinition>> matchingIdentityProviders =
                    allIdentityProviders.entrySet().stream()
                            .filter(idp -> {
                                final List<String> emailDomains = Optional.ofNullable(idp.getValue().getEmailDomain())
                                        .orElse(emptyList());
                                return emailDomains.contains(loginHintParam);
                            }).toList();
            if (matchingIdentityProviders.size() > 1) {
                throw new IllegalStateException(
                        "There is a misconfiguration with the identity provider(s). Please contact your system administrator."
                );
            }
            if (matchingIdentityProviders.size() == 1) {
                final Map.Entry<String, AbstractIdentityProviderDefinition> idpForRedirect = matchingIdentityProviders.getFirst();
                log.debug("Setting redirect from email domain login hint to: {}", idpForRedirect);
                return idpForRedirect;
            }
            return null;
        }

        // login hint was provided and could be parsed into JSON format
        log.debug("Received login hint: {}", UaaStringUtils.getCleanedUserControlString(loginHintParam));
        log.debug("Received login hint with origin: {}", uaaLoginHint.getOrigin());

        if (OriginKeys.UAA.equals(uaaLoginHint.getOrigin()) || OriginKeys.LDAP.equals(uaaLoginHint.getOrigin())) {
            if (allowedIdentityProviderKeys == null || allowedIdentityProviderKeys.contains(uaaLoginHint.getOrigin())) {
                // in case of uaa/ldap, pass value to login page
                model.addAttribute(LOGIN_HINT_ATTRIBUTE, loginHintParam);
                samlIdentityProviders.clear();
                oauthIdentityProviders.clear();
            } else {
                model.addAttribute(ERROR_ATTRIBUTE, "invalid_login_hint");
            }

            return null;
        }

        // for oidc/saml, trigger the redirect
        if (loginHintProvider != null) {
            log.debug("Setting redirect from origin login_hint to: {}", loginHintProvider);
            return loginHintProvider;
        }
        log.debug("Client does not allow provider for login_hint with origin key: {}", uaaLoginHint.getOrigin());
        model.addAttribute(ERROR_ATTRIBUTE, "invalid_login_hint");
        return null;
    }

    @RequestMapping(value = {"/delete_saved_account"})
    public String deleteSavedAccount(HttpServletRequest request, HttpServletResponse response, String userId) {
        Cookie cookie = UaaUrlUtils.createSavedCookie(userId, null);
        cookie.setMaxAge(0);
        cookie.setPath(request.getContextPath() + "/login");
        cookie.setSecure(true);
        response.addCookie(cookie);
        return "redirect:/login";
    }

    private String redirectToExternalProvider(AbstractIdentityProviderDefinition idpForRedirect, String idpOriginKey, HttpServletRequest request) {
        if (idpForRedirect != null) {
            if (idpForRedirect instanceof SamlIdentityProviderDefinition samlIdentityProviderDefinition) {
                String url = SamlRedirectUtils.getIdpRedirectUrl(samlIdentityProviderDefinition);
                return "redirect:/" + url;
            } else if (idpForRedirect instanceof AbstractExternalOAuthIdentityProviderDefinition providerDefinition) {
                String redirectUrl = getRedirectUrlForExternalOAuthIDP(request, idpOriginKey, providerDefinition);
                return REDIRECT + redirectUrl;
            }
        }
        return null;
    }

    private String getRedirectUrlForExternalOAuthIDP(HttpServletRequest request, String idpOriginKey, AbstractExternalOAuthIdentityProviderDefinition definition) {
        String idpAuthenticationUrl = externalOAuthProviderConfigurator.getIdpAuthenticationUrl(definition, idpOriginKey, request);
        if (request.getParameter(USERNAME_PARAMETER) != null && definition.getUserPropagationParameter() != null) {
            idpAuthenticationUrl = UriComponentsBuilder.fromUriString(idpAuthenticationUrl).queryParam(definition.getUserPropagationParameter(), request.getParameter(USERNAME_PARAMETER)).build().toUriString();
        }
        return idpAuthenticationUrl;
    }

    private Map<String, SamlIdentityProviderDefinition> getSamlIdentityProviderDefinitions(List<String> allowedIdps) {
        List<SamlIdentityProviderDefinition> filteredIdps = idpDefinitions.getIdentityProviderDefinitions(allowedIdps, IdentityZoneHolder.get());
        return filteredIdps.stream().collect(new MapCollector<>(SamlIdentityProviderDefinition::getIdpEntityAlias, idp -> idp));
    }

    private Map<String, SamlIdentityProviderDefinition> addDefaultSamlMap(Map<String, SamlIdentityProviderDefinition> list, List<String> allowedIdps, String defaultIdp) {
        Map<String, SamlIdentityProviderDefinition> defaultList = list == null ? new HashMap<>() : list;
        IdentityProvider samlIdP = getIdentityProviderByOrigin(allowedIdps, defaultIdp);
        if (samlIdP != null && samlIdP.getConfig() instanceof SamlIdentityProviderDefinition samlDefinition) {
            defaultList.putIfAbsent(samlDefinition.getIdpEntityAlias(), samlDefinition);
        }
        return defaultList;
    }

    private Map<String, AbstractExternalOAuthIdentityProviderDefinition> addDefaultOauthMap(Map<String, AbstractExternalOAuthIdentityProviderDefinition> list, List<String> allowedIdps, String defaultIdp) {
        Map<String, AbstractExternalOAuthIdentityProviderDefinition> defaultList = list == null ? new HashMap<>() : list;
        IdentityProvider oauthIdP = getIdentityProviderByOrigin(allowedIdps, defaultIdp);
        if (oauthIdP != null && oauthIdP.getConfig() instanceof AbstractExternalOAuthIdentityProviderDefinition oDefinition) {
            defaultList.putIfAbsent(oauthIdP.getOriginKey(), oDefinition);
        }
        return defaultList;
    }

    private IdentityProvider getIdentityProviderByOrigin(List<String> allowedIdps, String originKey) {
        IdentityProvider identityProvider = null;
        try {
            if (originKey != null && (allowedIdps == null || allowedIdps.contains(originKey))) {
                identityProvider = providerProvisioning.retrieveByOrigin(originKey, IdentityZoneHolder.get().getId());
            }
        } catch (EmptyResultDataAccessException ignored) {
            // ignore
        }
        return identityProvider;
    }

    protected Map<String, AbstractExternalOAuthIdentityProviderDefinition> getOauthIdentityProviderDefinitions(List<String> allowedIdps) {
        List<IdentityProvider> identityProviders = externalOAuthProviderConfigurator.retrieveActiveByTypes(
                IdentityZoneHolder.get().getId(),
                OIDC10, OAUTH20
        );

        return identityProviders.stream()
                .filter(p -> allowedIdps == null || allowedIdps.contains(p.getOriginKey()))
                .collect(idpsMapCollector);
    }

    private boolean hasSavedOauthAuthorizeRequest(HttpSession session) {
        if (session == null || SessionUtils.getSavedRequestSession(session) == null) {
            return false;
        }
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
        String redirectUrl = savedRequest.getRedirectUrl();
        String[] clientIds = savedRequest.getParameterValues(CLIENT_ID_PARAMETER);
        return redirectUrl != null && redirectUrl.contains("/oauth/authorize") && clientIds != null && clientIds.length != 0;
    }

    private Map<String, Object> getClientInfo(HttpSession session) {
        if (!hasSavedOauthAuthorizeRequest(session)) {
            return null;
        }
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
        String[] clientIds = savedRequest.getParameterValues(CLIENT_ID_PARAMETER);
        try {
            ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientIds[0], IdentityZoneHolder.get().getId());
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
            List<String> exclude,
            String origin,
            Map<String, SamlIdentityProviderDefinition> samlIdentityProviders,
            Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdentityProviders,
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
        for (AbstractExternalOAuthIdentityProviderDefinition oauthIdp : oauthIdentityProviders.values()) {
            if (oauthIdp.isShowLinkText()) {
                model.addAttribute(SHOW_LOGIN_LINKS, true);
                noIdpsPresent = false;
                break;
            }
        }

        //make the list writeable
        final List<String> excludedPrompts = new LinkedList<>(exclude);

        if (noIdpsPresent) {
            excludedPrompts.add(PASSCODE);
        }
        if (!returnLoginPrompts) {
            excludedPrompts.add(USERNAME_PARAMETER);
            excludedPrompts.add("password");
        }

        List<Prompt> prompts;
        IdentityZoneConfiguration zoneConfiguration = IdentityZoneHolder.get().getConfig();
        if (isNull(zoneConfiguration)) {
            zoneConfiguration = new IdentityZoneConfiguration();
        }
        prompts = zoneConfiguration.getPrompts();
        if (origin != null) {
            IdentityProvider providerForOrigin = null;
            try {
                providerForOrigin = providerProvisioning.retrieveByOrigin(origin, IdentityZoneHolder.get().getId());
            } catch (DataAccessException ignored) {
                // ignore
            }
            if (providerForOrigin != null && providerForOrigin.getConfig() instanceof OIDCIdentityProviderDefinition oidcConfig) {
                List<Prompt> providerPrompts = oidcConfig.getPrompts();
                if (providerPrompts != null) {
                    prompts = providerPrompts;
                }
            }
        }
        Map<String, String[]> map = new LinkedHashMap<>();
        for (Prompt prompt : prompts) {
            String[] details = prompt.getDetails();
            if (PASSCODE.equals(prompt.getName()) && !IdentityZoneHolder.isUaa()) {
                String urlInPasscode = extractUrlFromString(prompt.getDetails()[1]);
                if (hasText(urlInPasscode)) {
                    String[] newDetails = new String[details.length];
                    System.arraycopy(details, 0, newDetails, 0, details.length);
                    newDetails[1] = newDetails[1].replace(urlInPasscode, addSubdomainToUrl(urlInPasscode, IdentityZoneHolder.get().getSubdomain()));
                    details = newDetails;
                }
            }
            map.put(prompt.getName(), details);
        }
        for (String excludeThisPrompt : excludedPrompts) {
            map.remove(excludeThisPrompt);
        }
        model.addAttribute("prompts", map);
    }

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

    @PostMapping(value = "/origin-chooser")
    public String loginUsingOrigin(@RequestParam(required = false, name = LOGIN_HINT_ATTRIBUTE) String loginHint) {
        if (!StringUtils.hasText(loginHint)) {
            return "redirect:/login?discoveryPerformed=true";
        }
        UaaLoginHint uaaLoginHint = new UaaLoginHint(loginHint);
        return "redirect:/login?discoveryPerformed=true&login_hint=" + URLEncoder.encode(uaaLoginHint.toString(), UTF_8);
    }

    @PostMapping(value = "/login/idp_discovery")
    public String discoverIdentityProvider(@RequestParam String email, @RequestParam(required = false) String skipDiscovery, @RequestParam(required = false, name = LOGIN_HINT_ATTRIBUTE) String loginHint, @RequestParam(required = false, name = USERNAME_PARAMETER) String username, Model model, HttpSession session, HttpServletRequest request) {
        ClientDetails clientDetails = null;
        if (hasSavedOauthAuthorizeRequest(session)) {
            SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
            String[] clientIds = savedRequest.getParameterValues(CLIENT_ID_PARAMETER);
            try {
                clientDetails = clientDetailsService.loadClientByClientId(clientIds[0], IdentityZoneHolder.get().getId());
            } catch (NoSuchClientException ignored) {
                // ignore
            }
        }
        if (StringUtils.hasText(loginHint)) {
            model.addAttribute(LOGIN_HINT_ATTRIBUTE, loginHint);
        }
        List<IdentityProvider> identityProviders = DomainFilter.filter(providerProvisioning.retrieveActive(IdentityZoneHolder.get().getId()), clientDetails, email, false);

        if (!StringUtils.hasText(skipDiscovery) && identityProviders.size() == 1) {
            IdentityProvider matchedIdp = identityProviders.getFirst();
            if (matchedIdp.getType().equals(UAA)) {
                model.addAttribute(LOGIN_HINT_ATTRIBUTE, new UaaLoginHint("uaa").toString());
                return goToPasswordPage(email, model);
            } else {
                String redirectUrl;
                if ((redirectUrl = redirectToExternalProvider(matchedIdp.getConfig(), matchedIdp.getOriginKey(), request)) != null) {
                    return redirectUrl;
                }
            }
        }

        if (StringUtils.hasText(email)) {
            model.addAttribute(EMAIL_ATTRIBUTE, email);
        }
        if (StringUtils.hasText(username)) {
            model.addAttribute(USERNAME_PARAMETER, username);
        }
        return "redirect:/login?discoveryPerformed=true";
    }

    private String goToPasswordPage(String email, Model model) {
        model.addAttribute(ZONE_NAME, IdentityZoneHolder.get().getName());
        model.addAttribute(EMAIL_ATTRIBUTE, email);
        String forgotPasswordLink;
        if ((forgotPasswordLink = getSelfServiceLinks().get(FORGOT_PASSWORD_LINK)) != null) {
            model.addAttribute(FORGOT_PASSWORD_LINK, forgotPasswordLink);
        }
        return "idp_discovery/password";
    }

    @PostMapping(value = "/autologin")
    @ResponseBody
    public AutologinResponse generateAutologinCode(@RequestBody AutologinRequest request,
            @RequestHeader(value = "Authorization", required = false) String auth) {

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
        String credentials = new String(getDecoder().decode(base64Credentials.getBytes()), UTF_8);
        // credentials = username:password
        final String[] values = credentials.split(":", 2);
        if (values.length == 0) {
            throw new BadCredentialsException("Invalid authorization header.");
        }
        String clientId = values[0];
        Map<String, String> codeData = new HashMap<>();
        codeData.put(CLIENT_ID_PARAMETER, clientId);
        codeData.put(USERNAME_PARAMETER, username);
        if (userAuthentication != null && userAuthentication.getPrincipal() instanceof UaaPrincipal p) {
            codeData.put("user_id", p.getId());
            codeData.put(OriginKeys.ORIGIN, p.getOrigin());
        }
        ExpiringCode expiringCode = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000), ExpiringCodeType.AUTOLOGIN.name(), IdentityZoneHolder.get().getId());

        return new AutologinResponse(expiringCode.getCode());
    }

    @GetMapping(value = "/autologin")
    public String performAutologin(HttpSession session) {
        String redirectLocation = "home";
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
        if (savedRequest != null && savedRequest.getRedirectUrl() != null) {
            redirectLocation = savedRequest.getRedirectUrl();
        }

        return REDIRECT + redirectLocation;
    }

    @GetMapping(value = "/login_implicit")
    public String captureImplicitValuesUsingJavascript() {
        return "login_implicit";
    }

    @GetMapping(value = "/login/callback/{origin}")
    public String handleExternalOAuthCallback(final HttpSession session, @PathVariable String origin) {
        String redirectLocation = "/home";
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(session);
        if (savedRequest != null && savedRequest.getRedirectUrl() != null) {
            redirectLocation = savedRequest.getRedirectUrl();
        }

        return REDIRECT + redirectLocation;
    }

    private Map<String, ?> getLinksInfo() {

        Map<String, Object> model = new HashMap<>();
        model.put(OriginKeys.UAA, addSubdomainToUrl(baseUrl, IdentityZoneHolder.get().getSubdomain()));
        if (baseUrl.contains("localhost:")) {
            model.put(LOGIN, addSubdomainToUrl(baseUrl, IdentityZoneHolder.get().getSubdomain()));
        } else if (hasText(externalLoginUrl)) {
            model.put(LOGIN, externalLoginUrl);
        } else {
            model.put(LOGIN, addSubdomainToUrl(baseUrl.replaceAll(OriginKeys.UAA, LOGIN), IdentityZoneHolder.get().getSubdomain()));
        }
        model.putAll(getSelfServiceLinks());
        return model;
    }

    protected Map<String, String> getSelfServiceLinks() {
        Map<String, String> selfServiceLinks = new HashMap<>();
        IdentityZone zone = IdentityZoneHolder.get();
        IdentityProvider<UaaIdentityProviderDefinition> uaaIdp = providerProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        boolean disableInternalUserManagement = uaaIdp.getConfig() != null && uaaIdp.getConfig().isDisableInternalUserManagement();

        boolean selfServiceLinksEnabled = zone.getConfig() == null || zone.getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled();

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

    static class SavedAccountOptionModel extends SavedAccountOption {
        /**
         * These must be public. They are accessed in templates.
         */
        public int red;
        public int green;
        public int blue;

        void assignColors(Color color) {
            red = color.getRed();
            blue = color.getBlue();
            green = color.getGreen();
        }
    }
}
