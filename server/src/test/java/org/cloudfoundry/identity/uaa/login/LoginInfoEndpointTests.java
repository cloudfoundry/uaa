package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.MfaChecker;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.*;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.HttpMediaTypeNotAcceptableException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.sql.Timestamp;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.*;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LoginInfoEndpointTests {

    private static final String HTTP_LOCALHOST_8080_UAA = "http://localhost:8080/uaa";
    private final String BASE_URL = "http://someurl";
    private UaaPrincipal marissa;
    private List<Prompt> prompts;
    private ExtendedModelMap model;
    private SamlIdentityProviderConfigurator mockSamlIdentityProviderConfigurator;
    private List<SamlIdentityProviderDefinition> idps;
    private IdentityProviderProvisioning mockIdentityProviderProvisioning;
    private IdentityProvider uaaProvider;
    private XOAuthProviderConfigurator xoAuthProviderConfigurator;
    private MfaChecker mockMfaChecker;
    private RandomValueStringGenerator generator;
    private IdentityZoneManager mockIdentityZoneManager;
    private LoginInfoEndpoint loginInfoEndpoint;
    private IdentityZone mockIdentityZone;
    private IdentityZoneConfiguration mockIdentityZoneConfiguration;
    private Links.SelfService mockSelfService;
    private String currentIdentityZoneId;
    private String currentIdentityZoneSubdomain;
    private Links mockLinks;

    @BeforeEach
    void setUp() {
        generator = new RandomValueStringGenerator();
        currentIdentityZoneId = "currentIdentityZoneId-" + generator.generate();
        currentIdentityZoneSubdomain = "currentIdentityZoneSubdomain-" + generator.generate();

        mockIdentityZone = mock(IdentityZone.class);
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
        mockLinks = mock(Links.class);
        mockSelfService = mock(Links.SelfService.class);
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);
        when(mockIdentityZone.getId()).thenReturn(currentIdentityZoneId);
        when(mockIdentityZone.getSubdomain()).thenReturn(currentIdentityZoneSubdomain);
        when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
        when(mockIdentityZoneConfiguration.getLinks()).thenReturn(mockLinks);
        when(mockLinks.getSelfService()).thenReturn(mockSelfService);

        marissa = new UaaPrincipal("marissa-id", "marissa", "marissa@test.org", "origin", null, currentIdentityZoneId);
        prompts = new LinkedList<>();
        prompts.add(new Prompt("username", "text", "Email"));
        prompts.add(new Prompt("password", "password", "Password"));
        prompts.add(new Prompt("passcode", "text", "Temporary Authentication Code (Get one at " + HTTP_LOCALHOST_8080_UAA + "/passcode)"));
        mockSamlIdentityProviderConfigurator = mock(SamlIdentityProviderConfigurator.class);
        mockIdentityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        uaaProvider = new IdentityProvider();
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, currentIdentityZoneId)).thenReturn(uaaProvider);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, currentIdentityZoneId)).thenReturn(new IdentityProvider());
        idps = new LinkedList<>();
        idps.add(createIdentityProviderDefinition("awesome-idp", IdentityZone.getUaaZoneId()));
        idps.add(createIdentityProviderDefinition("my-client-awesome-idp", IdentityZone.getUaaZoneId()));
        OidcMetadataFetcher mockOidcMetadataFetcher = mock(OidcMetadataFetcher.class);
        xoAuthProviderConfigurator = new XOAuthProviderConfigurator(mockIdentityProviderProvisioning, mockOidcMetadataFetcher);
        mockMfaChecker = mock(MfaChecker.class);
        when(mockMfaChecker.isMfaEnabled(any())).thenReturn(false);
        model = new ExtendedModelMap();

        SamlIdentityProviderConfigurator mockSamlIdentityProviderConfigurator = mock(SamlIdentityProviderConfigurator.class);
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions()).thenReturn(Collections.emptyList());
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitionsForZone(any())).thenReturn(Collections.emptyList());

        Links globalLinks = new Links().setSelfService(new Links.SelfService().setPasswd(null).setSignup(null));

        loginInfoEndpoint = new LoginInfoEndpoint(null,
                BASE_URL,
                null,
                mockSamlIdentityProviderConfigurator,
                null,
                null,
                null,
                mockIdentityProviderProvisioning,
                xoAuthProviderConfigurator,
                globalLinks,
                mockMfaChecker,
                mockIdentityZoneManager);
    }

    @Test
    void loginReturnsSystemZone() throws HttpMediaTypeNotAcceptableException {
        when(mockIdentityZone.getName()).thenReturn(IdentityZone.getUaaZoneId());
        loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest(), Collections.singletonList(MediaType.TEXT_HTML));
        assertEquals(IdentityZone.getUaaZoneId(), model.asMap().get("zone_name"));
    }

    @Test
    void alreadyLoggedInRedirectsToHome() throws HttpMediaTypeNotAcceptableException {
        UaaAuthentication authentication = mock(UaaAuthentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        String result = loginInfoEndpoint.loginForHtml(model, authentication, new MockHttpServletRequest(), Collections.singletonList(MediaType.TEXT_HTML));
        assertEquals("redirect:/home", result);
    }

    @Test
    void deleteSavedAccount() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String userId = "testUserId";
        String result = loginInfoEndpoint.deleteSavedAccount(request, response, userId);
        Cookie[] cookies = response.getCookies();
        assertEquals(cookies.length, 1);
        assertEquals(cookies[0].getName(), "Saved-Account-" + userId);
        assertEquals(cookies[0].getMaxAge(), 0);
        assertEquals("redirect:/login", result);
    }

    @Test
    void savedAccountsPopulatedOnModel() throws UnsupportedEncodingException, HttpMediaTypeNotAcceptableException {
        assertThat(model, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin(OriginKeys.UAA);

        Cookie cookie1 = new Cookie("Saved-Account-xxxx", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        savedAccount.setUsername("tim");
        savedAccount.setEmail("tim@example.org");
        savedAccount.setUserId("zzzz");
        savedAccount.setOrigin("ldap");
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        request.setCookies(cookie1, cookie2);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));

        assertThat(model, hasKey("savedAccounts"));
        assertThat(model.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) model.get("savedAccounts");
        assertThat(savedAccounts, hasSize(2));

        SavedAccountOption savedAccount0 = savedAccounts.get(0);
        assertThat(savedAccount0, notNullValue());
        assertEquals("bob", savedAccount0.getUsername());
        assertEquals("bob@example.com", savedAccount0.getEmail());
        assertEquals(OriginKeys.UAA, savedAccount0.getOrigin());
        assertEquals("xxxx", savedAccount0.getUserId());

        SavedAccountOption savedAccount1 = savedAccounts.get(1);
        assertThat(savedAccount1, notNullValue());
        assertEquals("tim", savedAccount1.getUsername());
        assertEquals("tim@example.org", savedAccount1.getEmail());
        assertEquals("ldap", savedAccount1.getOrigin());
        assertEquals("zzzz", savedAccount1.getUserId());
    }

    @Test
    void ignoresBadJsonSavedAccount() throws HttpMediaTypeNotAcceptableException {
        assertThat(model, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin(OriginKeys.UAA);
        Cookie cookieGood = new Cookie("Saved-Account-xxxx", JsonUtils.writeValueAsString(savedAccount));

        Cookie cookieBadJson = new Cookie("Saved-Account-Bad", "{");

        request.setCookies(cookieGood, cookieBadJson);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));

        assertThat(model, hasKey("savedAccounts"));
        assertThat(model.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) model.get("savedAccounts");
        assertThat(savedAccounts, hasSize(1));
    }

    @Test
    void savedAccountsEncodedAndUnEncoded() throws UnsupportedEncodingException, HttpMediaTypeNotAcceptableException {
        assertThat(model, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bill");
        savedAccount.setEmail("bill@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin(OriginKeys.UAA);
        // write Cookie1 without URLencode into value, situation before this correction
        Cookie cookie1 = new Cookie("Saved-Account-xxxx", JsonUtils.writeValueAsString(savedAccount));

        savedAccount.setUsername("bill");
        savedAccount.setEmail("bill@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin(OriginKeys.UAA);
        // write Cookie2 with URLencode into value, situation after this correction
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        request.setCookies(cookie1, cookie2);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));

        assertThat(model, hasKey("savedAccounts"));
        assertThat(model.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) model.get("savedAccounts");
        assertThat(savedAccounts, hasSize(2));
        // evaluate that both cookies can be parsed out has have same values
        SavedAccountOption savedAccount0 = savedAccounts.get(0);
        assertThat(savedAccount0, notNullValue());
        assertEquals("bill", savedAccount0.getUsername());
        assertEquals("bill@example.com", savedAccount0.getEmail());
        assertEquals(OriginKeys.UAA, savedAccount0.getOrigin());
        assertEquals("xxxx", savedAccount0.getUserId());

        SavedAccountOption savedAccount1 = savedAccounts.get(1);
        assertThat(savedAccount1, notNullValue());
        assertEquals("bill", savedAccount1.getUsername());
        assertEquals("bill@example.com", savedAccount1.getEmail());
        assertEquals(OriginKeys.UAA, savedAccount1.getOrigin());
        assertEquals("xxxx", savedAccount1.getUserId());
    }

    @Test
    void savedAccountsInvalidCookie() throws HttpMediaTypeNotAcceptableException {
        assertThat(model, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin(OriginKeys.UAA);

        Cookie cookie1 = new Cookie("Saved-Account-xxxx", "%2");

        request.setCookies(cookie1);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));

        assertThat(model, hasKey("savedAccounts"));
        assertThat(model.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) model.get("savedAccounts");
        assertThat(savedAccounts, hasSize(0));
    }

    @Test
    void loginReturnsOtherZone() throws HttpMediaTypeNotAcceptableException {
        when(mockIdentityZone.getName()).thenReturn("some_other_zone");
        assertFalse(model.containsAttribute("zone_name"));
        loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest(), Collections.singletonList(MediaType.TEXT_HTML));
        assertEquals("some_other_zone", model.asMap().get("zone_name"));
    }

    @Test
    // TODO: This is really six tests. Make it so.
    void customSelfserviceLinks_ApplyToAllZone_Html() throws HttpMediaTypeNotAcceptableException {
        when(mockSelfService.isSelfServiceLinksEnabled()).thenReturn(true);
        when(mockSelfService.getSignup()).thenReturn("http://custom_signup_link");
        when(mockSelfService.getPasswd()).thenReturn("http://custom_passwd_link");

        loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest(), Collections.singletonList(MediaType.TEXT_HTML));
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", model);
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", loginInfoEndpoint.getSelfServiceLinks());

        // null zone config
        // null global
        // use defaults
        when(mockIdentityZone.getConfig()).thenReturn(null);
        validateSelfServiceLinks("/create_account", "/forgot_password", loginInfoEndpoint.getSelfServiceLinks());

        // null zone config
        // with globals
        // use globals
        when(mockIdentityZone.getConfig()).thenReturn(null);
        Links globalLinks = new Links();
        globalLinks.setSelfService(new Links.SelfService());
        globalLinks.getSelfService().setSelfServiceLinksEnabled(true);
        globalLinks.getSelfService().setSignup("/global-signup");
        globalLinks.getSelfService().setPasswd("/global-passwd");
        setGlobalLinks(loginInfoEndpoint, globalLinks);
        validateSelfServiceLinks("/global-signup", "/global-passwd", loginInfoEndpoint.getSelfServiceLinks());

        // has zone config - with null fields
        // with globals
        // use globals
        Links.SelfService emptySelfService = new Links.SelfService();
        emptySelfService.setSelfServiceLinksEnabled(true);
        emptySelfService.setSignup(null);
        emptySelfService.setPasswd(null);
        when(mockLinks.getSelfService()).thenReturn(emptySelfService);
        validateSelfServiceLinks("/global-signup", "/global-passwd", loginInfoEndpoint.getSelfServiceLinks());

        // has zone config - with null fields
        // with globals - using variables
        // use globals - resolving the variables
        globalLinks.getSelfService().setSelfServiceLinksEnabled(true);
        globalLinks.getSelfService().setSignup("/signup?domain={zone.subdomain}");
        globalLinks.getSelfService().setPasswd("/passwd?id={zone.id}");
        validateSelfServiceLinks("/signup?domain=" + currentIdentityZoneSubdomain, "/passwd?id=" + currentIdentityZoneId, loginInfoEndpoint.getSelfServiceLinks());

        // has zone config
        // with globals - using variables
        // uses zone configuration
        when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
        when(mockIdentityZoneConfiguration.getLinks()).thenReturn(mockLinks);
        when(mockLinks.getSelfService()).thenReturn(mockSelfService);
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", loginInfoEndpoint.getSelfServiceLinks());

        // has zone config - using variables
        // with globals - using variables
        // uses zone configuration - resolving the variables
        when(mockSelfService.getSignup()).thenReturn("/local_signup?domain={zone.subdomain}");
        when(mockSelfService.getPasswd()).thenReturn("/local_passwd?id={zone.id}");
        validateSelfServiceLinks("/local_signup?domain=" + currentIdentityZoneSubdomain, "/local_passwd?id=" + currentIdentityZoneId, loginInfoEndpoint.getSelfServiceLinks());
    }

    void validateSelfServiceLinks(String signup, String passwd, Model model) {
        Map<String, String> links = (Map<String, String>) model.asMap().get("links");
        validateSelfServiceLinks(signup, passwd, links);
    }

    void validateSelfServiceLinks(String signup, String passwd, Map<String, String> links) {
        assertEquals(signup, links.get("createAccountLink"));
        assertEquals(passwd, links.get("forgotPasswordLink"));
        //json links
        assertEquals(signup, links.get("register"));
        assertEquals(passwd, links.get("passwd"));
    }

    @Test
    void discoverIdentityProviderCarriesEmailIfProvided() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        loginInfoEndpoint.discoverIdentityProvider("testuser@fake.com", "true", null, model, session, request);

        assertEquals(model.get("email"), "testuser@fake.com");
    }

    @Test
    void discoverIdentityProviderCarriesLoginHintIfProvided() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        String loginHint = "{\"origin\":\"my-OIDC-idp1\"}";
        loginInfoEndpoint.discoverIdentityProvider("testuser@fake.com", "true", loginHint, model, session, request);

        assertEquals(loginHint, model.get("login_hint"));
    }

    @Test
    void discoverIdentityProviderWritesLoginHintIfOnlyUaa() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        UaaIdentityProviderDefinition uaaConfig = new UaaIdentityProviderDefinition();
        uaaConfig.setEmailDomain(Collections.singletonList("fake.com"));
        uaaProvider.setConfig(uaaConfig);
        uaaProvider.setType(OriginKeys.UAA);
        when(mockIdentityProviderProvisioning.retrieveActive(currentIdentityZoneId)).thenReturn(Collections.singletonList(uaaProvider));

        loginInfoEndpoint.discoverIdentityProvider("testuser@fake.com", null, null, model, session, request);

        String loginHint = "{\"origin\":\"uaa\"}";
        assertEquals(loginHint, model.get("login_hint"));
    }

    @Test
    void use_login_url_if_present() {
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(true);
        check_links_urls(IdentityZone.getUaa());
    }

    @Test
    void use_login_url_if_present_in_zone() {
        IdentityZone zone = MultitenancyFixture.identityZone("testId", "testSubdomain");
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(false);
        check_links_urls(zone);
    }

    @Test
    void mfa_prompt_in_default_zone() {
        IdentityZone zone = IdentityZone.getUaa();
        when(mockMfaChecker.isMfaEnabled(zone)).thenReturn(true);
        String baseUrl = check_links_urls(zone);
        Map mapPrompts = (Map) model.get("prompts");
        assertNotNull(mapPrompts.get("mfaCode"));
        assertEquals(
                "MFA Code ( Register at " + addSubdomainToUrl(baseUrl, null) + " )",
                ((String[]) mapPrompts.get("mfaCode"))[1]
        );
    }

    @Test
    void mfa_prompt_in_non_default_zone() {
        IdentityZone zone = MultitenancyFixture.identityZone("testId", "tEstSubdoMaIn");
        when(mockMfaChecker.isMfaEnabled(zone)).thenReturn(true);
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(false);
        String baseUrl = check_links_urls(zone);
        Map mapPrompts = (Map) model.get("prompts");
        assertNotNull(mapPrompts.get("mfaCode"));
        assertEquals(
                "MFA Code ( Register at " + addSubdomainToUrl(baseUrl, "testsubdomain") + " )",
                ((String[]) mapPrompts.get("mfaCode"))[1]
        );
    }

    String check_links_urls(IdentityZone zone) {
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(zone);
        zone.getConfig().setPrompts(prompts);
        String baseUrl = "http://uaa.domain.com";
        setBaseUrl(loginInfoEndpoint, baseUrl);
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        assertEquals(addSubdomainToUrl(baseUrl, zone.getSubdomain()), ((Map<String, String>) model.asMap().get("links")).get("uaa"));
        assertEquals(addSubdomainToUrl(baseUrl.replace("uaa", "login"), zone.getSubdomain()), ((Map<String, String>) model.asMap().get("links")).get("login"));

        String loginBaseUrl = "http://external-login.domain.com";
        ReflectionTestUtils.setField(loginInfoEndpoint, "externalLoginUrl", loginBaseUrl);
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        assertEquals(addSubdomainToUrl(baseUrl, zone.getSubdomain()), ((Map<String, String>) model.asMap().get("links")).get("uaa"));
        assertEquals(loginBaseUrl, ((Map<String, String>) model.asMap().get("links")).get("login"));

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(zone))).thenReturn(idps);
        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        Map mapPrompts = (Map) model.get("prompts");
        assertNotNull(mapPrompts.get("passcode"));
        assertEquals("Temporary Authentication Code (Get one at " + addSubdomainToUrl(HTTP_LOCALHOST_8080_UAA, zone.getSubdomain()) + "/passcode)", ((String[]) mapPrompts.get("passcode"))[1]);
        return baseUrl;
    }

    @Test
    void no_self_service_links_if_self_service_disabled() {
        when(mockSelfService.isSelfServiceLinksEnabled()).thenReturn(false);
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("register"));
        assertNull(links.get("passwd"));
    }

    @Test
    void no_ui_links_for_json() {
        when(mockIdentityZone.getSubdomain()).thenReturn("");
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(any(), any())).thenReturn(idps);
        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);
        when(mockSelfService.isSelfServiceLinksEnabled()).thenReturn(true);
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("linkCreateAccountShow"));
        assertNull(links.get("fieldUsernameShow"));
        assertNull(links.get("forgotPasswordLink"));
        assertNull(links.get("createAccountLink"));
        assertEquals(BASE_URL, links.get("login"));
        assertEquals(BASE_URL, links.get("uaa"));
        assertEquals("/create_account", links.get("register"));
        assertEquals("/forgot_password", links.get("passwd"));
    }

    @Test
    void saml_links_for_json() {
        when(mockIdentityZone.getSubdomain()).thenReturn(null);
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(any(), any())).thenReturn(idps);
        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertEquals(BASE_URL, links.get("login"));
        assertTrue(model.get("idpDefinitions") instanceof Map);
        Map<String, String> idpDefinitions = (Map<String, String>) model.get("idpDefinitions");
        for (SamlIdentityProviderDefinition def : idps) {
            assertEquals(
                    "http://someurl/saml/discovery?returnIDParam=idp&entityID=" + loginInfoEndpoint.getZonifiedEntityId() + "&idp=" + def.getIdpEntityAlias() + "&isPassive=true",
                    idpDefinitions.get(def.getIdpEntityAlias())
            );
        }
    }

    @Test
    void saml_links_for_html() throws HttpMediaTypeNotAcceptableException {
        when(mockIdentityZone.getSubdomain()).thenReturn("");
        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);
        loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest("GET", BASE_URL), null);
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertEquals(BASE_URL, links.get("login"));
        assertTrue(model.get("idpDefinitions") instanceof Collection);
    }

    @Test
    void no_self_service_links_if_internal_user_management_disabled() {
        UaaIdentityProviderDefinition uaaIdentityProviderDefinition = new UaaIdentityProviderDefinition();
        uaaIdentityProviderDefinition.setDisableInternalUserManagement(true);
        uaaProvider.setConfig(uaaIdentityProviderDefinition);
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        Map<String, Object> links = (Map<String, Object>) model.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("register"));
        assertNull(links.get("passwd"));
        assertNull(links.get("createAccountLink"));
        assertNull(links.get("forgotPasswordLink"));
        assertNull(model.asMap().get("createAccountLink"));
        assertNull(model.asMap().get("forgotPasswordLink"));
    }

    @Test
    void no_usernamePasswordBoxes_if_internalAuth_and_ldap_disabled() throws HttpMediaTypeNotAcceptableException {
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(anyList(), any())).thenReturn(idps);

        IdentityProvider ldapIdentityProvider = new IdentityProvider();
        ldapIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, currentIdentityZoneId)).thenReturn(ldapIdentityProvider);

        IdentityProvider uaaIdentityProvider = new IdentityProvider();
        uaaIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, currentIdentityZoneId)).thenReturn(uaaIdentityProvider);

        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);

        loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest("GET", BASE_URL), null);
        assertFalse((Boolean) model.get("fieldUsernameShow"));
    }

    @Test
    void generatePasscodeForKnownUaaPrincipal() {
        Map<String, Object> model = new HashMap<>();
        ExpiringCodeStore mockExpiringCodeStore = spy(new InMemoryExpiringCodeStore());
        ReflectionTestUtils.setField(loginInfoEndpoint, "expiringCodeStore", mockExpiringCodeStore);
        assertEquals("passcode", loginInfoEndpoint.generatePasscode(model, marissa));
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<>(), new UaaAuthenticationDetails(new MockHttpServletRequest()));
        assertEquals("passcode", loginInfoEndpoint.generatePasscode(model, uaaAuthentication));
        ExpiringUsernameAuthenticationToken expiringUsernameAuthenticationToken = new ExpiringUsernameAuthenticationToken(marissa, "");
        UaaAuthentication samlAuthenticationToken = new LoginSamlAuthenticationToken(marissa, expiringUsernameAuthenticationToken).getUaaAuthentication(emptyList(), emptySet(), new LinkedMultiValueMap<>());
        assertEquals("passcode", loginInfoEndpoint.generatePasscode(model, samlAuthenticationToken));
        //token with a UaaPrincipal should always work
        assertEquals("passcode", loginInfoEndpoint.generatePasscode(model, expiringUsernameAuthenticationToken));
        verify(mockExpiringCodeStore, times(4)).generateCode(
                anyString(),
                any(Timestamp.class),
                anyString(),
                eq(currentIdentityZoneId));
        verify(mockExpiringCodeStore, times(4)).expireByIntent(
                anyString(),
                eq(currentIdentityZoneId));
    }

    @Test
    void generatePasscodeForUnknownUaaPrincipal() {
        Map<String, Object> model = new HashMap<>();
        ExpiringUsernameAuthenticationToken token = new ExpiringUsernameAuthenticationToken("princpal", "");
        assertThrows(LoginInfoEndpoint.UnknownPrincipalException.class,
                () -> loginInfoEndpoint.generatePasscode(model, token));
    }

    @Test
    // TODO: This feels like multiple tests.
    void promptLogic() throws HttpMediaTypeNotAcceptableException {
        when(mockMfaChecker.isMfaEnabled(any())).thenReturn(true);
        when(mockIdentityZoneConfiguration.getPrompts()).thenReturn(prompts);
        loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest("GET", BASE_URL), singletonList(MediaType.TEXT_HTML));
        assertNotNull(model.get("prompts"), "prompts attribute should be present");
        assertTrue(model.get("prompts") instanceof Map, "prompts should be a Map for Html content");
        Map mapPrompts = (Map) model.get("prompts");
        assertEquals(2, mapPrompts.size(), "there should be two prompts for html");
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNull(mapPrompts.get("passcode"));
        assertNull(mapPrompts.get("mfaCode"));

        model.clear();
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        assertNotNull(model.get("prompts"), "prompts attribute should be present");
        assertTrue(model.get("prompts") instanceof Map, "prompts should be a Map for JSON content");
        mapPrompts = (Map) model.get("prompts");
        assertEquals(3, mapPrompts.size(), "there should be two prompts for html");
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNotNull(mapPrompts.get("mfaCode"));
        assertNull(mapPrompts.get("passcode"));

        //add a SAML IDP, should make the passcode prompt appear
        model.clear();
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(mockIdentityZone))).thenReturn(idps);
        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        assertNotNull(model.get("prompts"), "prompts attribute should be present");
        assertTrue(model.get("prompts") instanceof Map, "prompts should be a Map for JSON content");
        mapPrompts = (Map) model.get("prompts");
        assertEquals(4, mapPrompts.size(), "there should be four prompts for html");
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNotNull(mapPrompts.get("passcode"));
        assertNotNull(mapPrompts.get("mfaCode"));

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(mockIdentityZone))).thenReturn(idps);

        IdentityProvider ldapIdentityProvider = new IdentityProvider();
        ldapIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, currentIdentityZoneId)).thenReturn(ldapIdentityProvider);

        IdentityProvider uaaIdentityProvider = new IdentityProvider();
        uaaIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, currentIdentityZoneId)).thenReturn(uaaIdentityProvider);

        model.clear();
        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));
        assertNotNull(model.get("prompts"), "prompts attribute should be present");
        mapPrompts = (Map) model.get("prompts");
        assertNull(mapPrompts.get("username"));
        assertNull(mapPrompts.get("password"));
        assertNotNull(mapPrompts.get("passcode"));
    }

    @Test
    void filterIdpsForDefaultZone() throws HttpMediaTypeNotAcceptableException {
        // mock session and saved request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl()).thenReturn("http://localhost:8080/uaa");
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        request.setSession(session);
        // mock SamlIdentityProviderConfigurator
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(isNull(), eq(mockIdentityZone))).thenReturn(idps);

        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        Iterator<SamlIdentityProviderDefinition> iterator = idpDefinitions.iterator();
        SamlIdentityProviderDefinition clientIdp = iterator.next();
        assertEquals("awesome-idp", clientIdp.getIdpEntityAlias());
        assertTrue(clientIdp.isShowSamlLink());

        clientIdp = iterator.next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertTrue(clientIdp.isShowSamlLink());
        assertEquals(true, model.asMap().get("fieldUsernameShow"));
        assertEquals(true, model.asMap().get("linkCreateAccountShow"));
    }

    @Test
    void filterIdpsWithNoSavedRequest() throws HttpMediaTypeNotAcceptableException {
        // mock SamlIdentityProviderConfigurator

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(mockIdentityZone))).thenReturn(idps);

        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);
        loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest(), Collections.singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        Iterator<SamlIdentityProviderDefinition> iterator = idpDefinitions.iterator();
        SamlIdentityProviderDefinition clientIdp = iterator.next();
        assertEquals("awesome-idp", clientIdp.getIdpEntityAlias());
        assertTrue(clientIdp.isShowSamlLink());

        clientIdp = iterator.next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertTrue(clientIdp.isShowSamlLink());
        assertEquals(true, model.asMap().get("fieldUsernameShow"));
        assertEquals(true, model.asMap().get("linkCreateAccountShow"));
    }

    @Test
    void filterIDPsForAuthcodeClientInDefaultZone() throws HttpMediaTypeNotAcceptableException {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-client-awesome-idp1", "my-client-awesome-idp2", OriginKeys.LDAP);

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);

        // mock SamlIdentityProviderConfigurator
        List<SamlIdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp1", OriginKeys.UAA));
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp2", currentIdentityZoneId));
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(eq(allowedProviders), eq(mockIdentityZone))).thenReturn(clientIDPs);

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);
        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockSamlIdentityProviderConfigurator);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        assertThat(idpDefinitions, PredicateMatcher.<SamlIdentityProviderDefinition>has(c -> c.getIdpEntityAlias().equals("my-client-awesome-idp1")));
        assertThat(idpDefinitions, PredicateMatcher.<SamlIdentityProviderDefinition>has(c -> c.isShowSamlLink()));
        assertEquals(true, model.asMap().get("fieldUsernameShow"));
        assertEquals(false, model.asMap().get("linkCreateAccountShow"));
    }

    @Test
    void filterIDPsForAuthcodeClientInOtherZone() throws HttpMediaTypeNotAcceptableException {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-client-awesome-idp1", "my-client-awesome-idp2");

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);

        // mock SamlIdentityProviderConfigurator
        List<SamlIdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp1", OriginKeys.UAA));
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp2", currentIdentityZoneId));
        SamlIdentityProviderConfigurator mockIDPConfigurator = mock(SamlIdentityProviderConfigurator.class);
        when(mockIDPConfigurator.getIdentityProviderDefinitions(eq(allowedProviders), eq(mockIdentityZone))).thenReturn(clientIDPs);

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);
        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockIDPConfigurator);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) model.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        assertThat(idpDefinitions, PredicateMatcher.<SamlIdentityProviderDefinition>has(c -> c.getIdpEntityAlias().equals("my-client-awesome-idp1")));
        assertThat(idpDefinitions, PredicateMatcher.<SamlIdentityProviderDefinition>has(c -> c.isShowSamlLink()));
        assertEquals(false, model.asMap().get("fieldUsernameShow"));
        assertEquals(false, model.asMap().get("linkCreateAccountShow"));
    }

    @Test
    void filterIDPsForAuthcodeClientWithNoAllowedIDPsInOtherZone() throws HttpMediaTypeNotAcceptableException {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId(eq("client-id"), anyString())).thenReturn(clientDetails);

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);
        // mock SamlIdentityProviderConfigurator
        SamlIdentityProviderConfigurator mockIDPConfigurator = mock(SamlIdentityProviderConfigurator.class);
        setSamlIdentityProviderConfigurator(loginInfoEndpoint, mockIDPConfigurator);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));
        verify(mockIDPConfigurator).getIdentityProviderDefinitions(null, mockIdentityZone);
    }

    @Test
    void allowedIdpsforClientOIDCProvider() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2", OriginKeys.LDAP);

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);

        List<IdentityProvider> clientAllowedIdps = new LinkedList<>();
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp1"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp2"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp3"));

        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(clientAllowedIdps);

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);
        loginInfoEndpoint.loginForHtml(model, null, request, Collections.singletonList(MediaType.TEXT_HTML));

        Map<String, AbstractXOAuthIdentityProviderDefinition> idpDefinitions = (Map<String, AbstractXOAuthIdentityProviderDefinition>) model.asMap().get("oauthLinks");
        assertEquals(2, idpDefinitions.size());
    }

    @Test
    void oauth_provider_links_shown() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        RawXOAuthIdentityProviderDefinition definition = new RawXOAuthIdentityProviderDefinition();

        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", currentIdentityZoneId);
        identityProvider.setConfig(definition);

        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), anyString())).thenReturn(Collections.singletonList(identityProvider));
        loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest(), Collections.singletonList(MediaType.TEXT_HTML));

        assertThat(model.get("showLoginLinks"), equalTo(true));
    }

    @Test
    void passcode_prompt_present_whenThereIsAtleastOneActiveOauthProvider() throws MalformedURLException {
        when(mockIdentityZoneConfiguration.getPrompts()).thenReturn(prompts);
        RawXOAuthIdentityProviderDefinition definition = new RawXOAuthIdentityProviderDefinition()
                .setAuthUrl(new URL("http://auth.url"))
                .setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", currentIdentityZoneId);
        identityProvider.setConfig(definition);

        when(mockIdentityProviderProvisioning.retrieveAll(true, currentIdentityZoneId)).thenReturn(Collections.singletonList(identityProvider));
        loginInfoEndpoint.infoForLoginJson(model, null, new MockHttpServletRequest("GET", BASE_URL));

        Map mapPrompts = (Map) model.get("prompts");
        assertNotNull(mapPrompts.get("passcode"));
    }

    @Test
    void we_return_both_oauth_and_oidc_providers() throws MalformedURLException {
        RawXOAuthIdentityProviderDefinition oauthDefinition = new RawXOAuthIdentityProviderDefinition()
                .setAuthUrl(new URL("http://auth.url"))
                .setTokenUrl(new URL("http://token.url"));
        OIDCIdentityProviderDefinition oidcDefinition = new OIDCIdentityProviderDefinition()
                .setAuthUrl(new URL("http://auth.url"))
                .setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oauthProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", OriginKeys.UAA);
        oauthProvider.setConfig(oauthDefinition);

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oidcProvider = MultitenancyFixture.identityProvider("oidc-idp-alias", currentIdentityZoneId);
        oidcProvider.setConfig(oidcDefinition);

        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), anyString())).thenReturn(Arrays.asList(oauthProvider, oidcProvider));
        assertEquals(2, loginInfoEndpoint.getOauthIdentityProviderDefinitions(null).size());
    }

    @Test
    void xoauthCallback_redirectsToHomeIfNoSavedRequest() {
        HttpSession session = new MockHttpSession();
        String redirectUrl = loginInfoEndpoint.handleXOAuthCallback(session);
        assertEquals("redirect:/home", redirectUrl);
    }

    @Test
    void xoauthCallback_redirectsToSavedRequestIfPresent() {
        HttpSession session = new MockHttpSession();
        DefaultSavedRequest savedRequest = Mockito.mock(DefaultSavedRequest.class);
        when(savedRequest.getRedirectUrl()).thenReturn("/some.redirect.url");
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        String redirectUrl = loginInfoEndpoint.handleXOAuthCallback(session);
        assertEquals("redirect:/some.redirect.url", redirectUrl);
    }

    @Test
    void loginWithInvalidMediaType() {
        assertThrows(HttpMediaTypeNotAcceptableException.class, () -> loginInfoEndpoint.loginForHtml(model, null, new MockHttpServletRequest(), Arrays.asList(MediaType.TEXT_XML)));
    }

    @Test
    void generateAutologinCodeFailsWhenMfaRequired() {
        doReturn(true).when(mockMfaChecker).isMfaEnabled(any(IdentityZone.class));

        assertThrowsWithMessageThat(BadCredentialsException.class,
                () -> loginInfoEndpoint.generateAutologinCode(mock(AutologinRequest.class), "Basic 1234"),
                is("MFA is required"));
    }

    @Test
    void performAutologinFailsWhenMfaRequired() {
        doReturn(true).when(mockMfaChecker).isMfaEnabled(any(IdentityZone.class));
        assertThrowsWithMessageThat(BadCredentialsException.class,
                () -> loginInfoEndpoint.performAutologin(new MockHttpSession()),
                is("MFA is required"));
    }

    @Test
    void loginHintEmailDomain() throws HttpMediaTypeNotAcceptableException, MalformedURLException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        IdentityProvider mockProvider = mock(IdentityProvider.class);
        when(mockProvider.getOriginKey()).thenReturn("my-OIDC-idp1");
        when(mockProvider.getType()).thenReturn(OriginKeys.OIDC10);
        AbstractXOAuthIdentityProviderDefinition mockOidcConfig = mock(OIDCIdentityProviderDefinition.class);
        when(mockOidcConfig.getAuthUrl()).thenReturn(new URL("http://localhost:8080/uaa"));
        when(mockOidcConfig.getRelyingPartyId()).thenReturn("client-id");
        when(mockOidcConfig.getResponseType()).thenReturn("token");
        when(mockOidcConfig.getEmailDomain()).thenReturn(Collections.singletonList("example.com"));
        when(mockProvider.getConfig()).thenReturn(mockOidcConfig);
        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), any())).thenReturn(Collections.singletonList(mockProvider));

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"example.com"});

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
        assertNull(model.get("login_hint"));
    }

    @Test
    void loginHintOriginUaa() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});


        loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", model.get("login_hint"));
    }

    @Test
    void loginHintOriginUaaDirectCall() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("login_hint", "{\"origin\":\"uaa\"}");

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);


        loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", model.get("login_hint"));
    }

    @Test
    void loginHintOriginUaaDoubleEncoded() throws UnsupportedEncodingException, HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{URLEncoder.encode("{\"origin\":\"uaa\"}", "utf-8")});


        loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertEquals(model.get("login_hint"), URLEncoder.encode("{\"origin\":\"uaa\"}", "utf-8"));
    }

    @Test
    void loginHintOriginUaaAllowedProvidersNull() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, null);
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});

        loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", model.get("login_hint"));
    }

    @Test
    void loginHintUaaNotAllowedLoginPageNotEmpty() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2");
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);
        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        List<IdentityProvider> clientAllowedIdps = new LinkedList<>();
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp1"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp2"));
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(clientAllowedIdps);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});


        loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertNull(model.get("login_hint"));
        assertFalse((Boolean) model.get("fieldUsernameShow"));
        assertEquals("invalid_login_hint", model.get("error"));
    }

    @Test
    void loginHintOriginUaaSkipAccountChooser() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});

        when(mockIdentityZoneConfiguration.isIdpDiscoveryEnabled()).thenReturn(true);
        when(mockIdentityZoneConfiguration.isAccountChooserEnabled()).thenReturn(true);

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", model.get("login_hint"));
        assertEquals("idp_discovery/password", redirect);
    }

    @Test
    void invalidLoginHintErrorOnDiscoveryPage() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"invalidorigin\"}"});

        when(mockIdentityZoneConfiguration.isIdpDiscoveryEnabled()).thenReturn(true);
        when(mockIdentityZoneConfiguration.isAccountChooserEnabled()).thenReturn(true);

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertEquals("idp_discovery/email", redirect);
    }

    @Test
    void loginHintOriginOidc() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});


        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Arrays.asList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
        assertNull(model.get("login_hint"));
    }

    @Test
    void loginHintOriginOidcForJson() throws MalformedURLException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});

        when(mockIdentityZoneConfiguration.getPrompts()).thenReturn(prompts);

        loginInfoEndpoint.infoForLoginJson(model, null, mockHttpServletRequest);

        assertNotNull(model.get("prompts"));
        assertTrue(model.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) model.get("prompts");
        assertEquals(3, returnedPrompts.size());
    }

    @Test
    void loginHintOriginInvalid() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});


        loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Arrays.asList(MediaType.TEXT_HTML));

        assertEquals("invalid_login_hint", model.get("error"));
    }

    @Test
    void getPromptsFromOIDCProvider() {
        List<Prompt> customPrompts = new ArrayList<>();
        customPrompts.add(new Prompt("username", "text", "MyEmail"));
        customPrompts.add(new Prompt("password", "password", "MyPassword"));
        customPrompts.add(new Prompt("passcode", "text", "MyTemporary Authentication Code (Get one at " + HTTP_LOCALHOST_8080_UAA + "/passcode)"));

        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("origin", "OIDC-without-prompts");
        IdentityProvider provider = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition oidcConfig = mock(OIDCIdentityProviderDefinition.class);

        when(oidcConfig.getPrompts()).thenReturn(customPrompts);
        when(provider.getConfig()).thenReturn(oidcConfig);
        when(mockIdentityProviderProvisioning.retrieveByOrigin("OIDC-without-prompts", currentIdentityZoneId)).thenReturn(provider);

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);


        loginInfoEndpoint.infoForLoginJson(model, null, mockHttpServletRequest);

        assertNotNull(model.get("prompts"));
        assertTrue(model.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) model.get("prompts");
        assertEquals(2, returnedPrompts.size());

        assertNotNull(returnedPrompts.get("username"));
        assertEquals("MyEmail", returnedPrompts.get("username")[1]);
        assertNotNull(returnedPrompts.get("password"));
        assertEquals("MyPassword", returnedPrompts.get("password")[1]);
    }

    @Test
    void getPromptsFromNonOIDCProvider() {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("origin", "non-OIDC");
        IdentityProvider provider = mock(IdentityProvider.class);
        SamlIdentityProviderDefinition samlConfig = mock(SamlIdentityProviderDefinition.class);
        when(provider.getConfig()).thenReturn(samlConfig);
        when(mockIdentityProviderProvisioning.retrieveByOrigin("non-OIDC", currentIdentityZoneId)).thenReturn(provider);

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        when(mockIdentityZoneConfiguration.getPrompts()).thenReturn(prompts);

        loginInfoEndpoint.infoForLoginJson(model, null, mockHttpServletRequest);

        assertNotNull(model.get("prompts"));
        assertTrue(model.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) model.get("prompts");
        assertEquals(2, returnedPrompts.size());
        assertNotNull(returnedPrompts.get("username"));
        assertEquals("Email", returnedPrompts.get("username")[1]);
        assertNotNull(returnedPrompts.get("password"));
        assertEquals("Password", returnedPrompts.get("password")[1]);
    }

    @Test
    void getPromptsFromNonExistentProvider() {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("origin", "non-OIDC");
        when(mockIdentityProviderProvisioning.retrieveByOrigin("non-OIDC", currentIdentityZoneId)).thenThrow(mock(DataAccessException.class));

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        when(mockIdentityZoneConfiguration.getPrompts()).thenReturn(prompts);

        loginInfoEndpoint.infoForLoginJson(model, null, mockHttpServletRequest);

        assertNotNull(model.get("prompts"));
        assertTrue(model.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) model.get("prompts");
        assertEquals(2, returnedPrompts.size());
        assertNotNull(returnedPrompts.get("username"));
        assertEquals("Email", returnedPrompts.get("username")[1]);
        assertNotNull(returnedPrompts.get("password"));
        assertEquals("Password", returnedPrompts.get("password")[1]);
    }

    @Test
    void getPromptsFromOIDCProviderWithoutPrompts() {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("origin", "OIDC-without-prompts");
        IdentityProvider provider = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition oidcConfig = mock(OIDCIdentityProviderDefinition.class);
        when(oidcConfig.getPrompts()).thenReturn(null);
        when(provider.getConfig()).thenReturn(oidcConfig);
        when(mockIdentityProviderProvisioning.retrieveByOrigin("OIDC-without-prompts", currentIdentityZoneId)).thenReturn(provider);

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        when(mockIdentityZoneConfiguration.getPrompts()).thenReturn(prompts);

        loginInfoEndpoint.infoForLoginJson(model, null, mockHttpServletRequest);

        assertNotNull(model.get("prompts"));
        assertTrue(model.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) model.get("prompts");
        assertEquals(2, returnedPrompts.size());

        assertNotNull(returnedPrompts.get("username"));
        assertEquals("Email", returnedPrompts.get("username")[1]);
        assertNotNull(returnedPrompts.get("password"));
        assertEquals("Password", returnedPrompts.get("password")[1]);
    }

    @Test
    void defaultProviderUaa() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        when(mockIdentityZoneConfiguration.getDefaultIdentityProvider()).thenReturn(OriginKeys.UAA);

        MultitenantClientServices clientDetailsService = mockClientService();
        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertEquals("login", redirect);
        assertEquals("{\"origin\":\"uaa\"}", model.get("login_hint"));
    }

    @Test
    void defaultProviderOIDC() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider();
        when(mockIdentityZoneConfiguration.getDefaultIdentityProvider()).thenReturn("my-OIDC-idp1");

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Arrays.asList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
    }

    @Test
    void defaultProviderOIDCLoginForJson() throws MalformedURLException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider();
        when(mockIdentityZoneConfiguration.getDefaultIdentityProvider()).thenReturn("my-OIDC-idp1");

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        when(mockIdentityZoneConfiguration.getPrompts()).thenReturn(prompts);

        loginInfoEndpoint.infoForLoginJson(model, null, mockHttpServletRequest);

        assertNotNull(model.get("prompts"));
        assertTrue(model.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) model.get("prompts");
        assertEquals(3, returnedPrompts.size());
    }

    @Test
    void defaultProviderBeforeDiscovery() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        mockOidcProvider();
        when(mockIdentityZoneConfiguration.getDefaultIdentityProvider()).thenReturn("my-OIDC-idp1");
        when(mockIdentityZoneConfiguration.isIdpDiscoveryEnabled()).thenReturn(true);
        when(mockIdentityZoneConfiguration.isAccountChooserEnabled()).thenReturn(true);

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        mockHttpServletRequest.setParameter("discoveryPerformed", "true");

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
    }

    @Test
    void loginHintOverridesDefaultProvider() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        when(mockIdentityZoneConfiguration.getDefaultIdentityProvider()).thenReturn(OriginKeys.UAA);

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});


        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Arrays.asList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
        assertNull(model.get("login_hint"));
    }

    @Test
    void loginHintLdapOverridesDefaultProviderUaa() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        when(mockIdentityZoneConfiguration.getDefaultIdentityProvider()).thenReturn(OriginKeys.UAA);

        MultitenantClientServices clientDetailsService = mockClientService();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"ldap\"}"});

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Arrays.asList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"ldap\"}", model.get("login_hint"));
        assertEquals("login", redirect);
    }

    @Test
    void defaultProviderInvalidFallback() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        when(mockIdentityZoneConfiguration.getDefaultIdentityProvider()).thenReturn("invalid");

        MultitenantClientServices clientDetailsService = mockClientService();
        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertEquals("login", redirect);
    }

    @Test
    void defaultProviderLdapWithAllowedOnlyOIDC() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = Collections.singletonList("my-OIDC-idp1");
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);

        mockOidcProvider();
        when(mockIdentityZoneConfiguration.getDefaultIdentityProvider()).thenReturn(OriginKeys.LDAP);

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Arrays.asList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
        assertFalse(model.containsKey("login_hint"));
    }

    @Test
    void allowedProvidersOnlyLDAPDoesNotUseInternalUsers() throws HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = Collections.singletonList("ldap");
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Arrays.asList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"ldap\"}", model.get("login_hint"));
        assertEquals("login", redirect);
    }

    @Test
    void allowedProvidersLoginHintDoesKeepExternalProviders() throws MalformedURLException, HttpMediaTypeNotAcceptableException {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", OriginKeys.UAA);
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);

        mockOidcProvider();

        setClientDetailsService(loginInfoEndpoint, clientDetailsService);

        String redirect = loginInfoEndpoint.loginForHtml(model, null, mockHttpServletRequest, Arrays.asList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", model.get("login_hint"));
        assertEquals("login", redirect);

        Map<String, String> oauthLinks = (Map<String, String>) model.get("oauthLinks");
        assertEquals(1, oauthLinks.size());
    }

    @Test
    void baseUrlIncludesLocalhost() {
        setBaseUrl(loginInfoEndpoint, "http://localhost:8080/uaa");
        when(mockIdentityZone.getSubdomain()).thenReturn("subdomain_for_zone");

        loginInfoEndpoint.infoForJson(model, null, new MockHttpServletRequest("GET", BASE_URL));

        Map<String, String> links = (Map<String, String>) model.asMap().get("links");

        assertThat(links.get("login"), is("http://subdomain_for_zone.localhost:8080/uaa"));
    }

    private MockHttpServletRequest getMockHttpServletRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl())
                .thenReturn("http://localhost:8080/uaa/oauth/authorize?client_id=identity&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        request.setSession(session);
        return request;
    }

    private static SamlIdentityProviderDefinition createIdentityProviderDefinition(
            final String idpEntityAlias,
            final String zoneId) {
        SamlIdentityProviderDefinition idp1 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation("metadataLocation for " + idpEntityAlias)
                .setIdpEntityAlias(idpEntityAlias)
                .setNameID("nameID for " + idpEntityAlias)
                .setMetadataTrustCheck(true)
                .setLinkText("link text for " + idpEntityAlias)
                .setIconUrl("icon url for " + idpEntityAlias)
                .setZoneId(zoneId);
        idp1.setIdpEntityAlias(idpEntityAlias);
        idp1.setShowSamlLink(true);
        idp1.setZoneId(zoneId);
        return idp1;
    }

    private IdentityProvider createOIDCIdentityProvider(String originKey) throws MalformedURLException {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oidcIdentityProvider = new IdentityProvider<>();
        oidcIdentityProvider.setOriginKey(originKey);
        oidcIdentityProvider.setType(OriginKeys.OIDC10);
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("https://" + originKey + ".com"));
        oidcIdentityProvider.setConfig(definition);

        return oidcIdentityProvider;

    }

    private MultitenantClientServices mockClientService() {
        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2", OriginKeys.LDAP, OriginKeys.UAA);
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", currentIdentityZoneId)).thenReturn(clientDetails);
        return clientDetailsService;
    }

    private void mockOidcProvider() throws MalformedURLException {
        IdentityProvider mockProvider = mock(IdentityProvider.class);
        when(mockProvider.getOriginKey()).thenReturn("my-OIDC-idp1");
        when(mockProvider.getType()).thenReturn(OriginKeys.OIDC10);
        AbstractXOAuthIdentityProviderDefinition mockOidcConfig = mock(OIDCIdentityProviderDefinition.class);
        when(mockOidcConfig.getAuthUrl()).thenReturn(new URL("http://localhost:8080/uaa"));
        when(mockOidcConfig.getRelyingPartyId()).thenReturn("client-id");
        when(mockOidcConfig.getResponseType()).thenReturn("token");
        when(mockProvider.getConfig()).thenReturn(mockOidcConfig);
        when(mockOidcConfig.isShowLinkText()).thenReturn(true);
        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), any())).thenReturn(Collections.singletonList(mockProvider));
    }

    private static void setBaseUrl(final LoginInfoEndpoint loginInfoEndpoint,
                                   final String baseUrl) {
        ReflectionTestUtils.setField(loginInfoEndpoint, "baseUrl", baseUrl);
    }

    private static void setGlobalLinks(final LoginInfoEndpoint loginInfoEndpoint,
                                       final Links globalLinks) {
        ReflectionTestUtils.setField(loginInfoEndpoint, "globalLinks", globalLinks);
    }

    private static void setClientDetailsService(final LoginInfoEndpoint loginInfoEndpoint,
                                                final ClientDetailsService clientDetailsService) {
        ReflectionTestUtils.setField(loginInfoEndpoint, "clientDetailsService", clientDetailsService);
    }

    private static void setSamlIdentityProviderConfigurator(final LoginInfoEndpoint loginInfoEndpoint,
                                                            final SamlIdentityProviderConfigurator samlIdentityProviderConfigurator) {
        ReflectionTestUtils.setField(loginInfoEndpoint, "idpDefinitions", samlIdentityProviderConfigurator);
    }
}