package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.MfaChecker;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.HttpMediaTypeNotAcceptableException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;
import java.util.function.Function;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.*;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(PollutionPreventionExtension.class)
class LoginInfoEndpointTests {

    private static final String HTTP_LOCALHOST_8080_UAA = "http://localhost:8080/uaa";
    private static final Links DEFAULT_GLOBAL_LINKS = new Links().setSelfService(new Links.SelfService().setPasswd(null).setSignup(null));
    private UaaPrincipal marissa;
    private List<Prompt> prompts;
    private ExtendedModelMap extendedModelMap;
    private SamlIdentityProviderConfigurator mockSamlIdentityProviderConfigurator;
    private List<SamlIdentityProviderDefinition> idps;
    private IdentityProviderProvisioning mockIdentityProviderProvisioning;
    private IdentityProvider uaaIdentityProvider;
    private IdentityZoneConfiguration originalConfiguration;
    private XOAuthProviderConfigurator configurator;
    private MfaChecker spiedMfaChecker;

    @BeforeEach
    void setUp() {
        IdentityZoneHolder.clear();
        marissa = new UaaPrincipal("marissa-id", "marissa", "marissa@test.org", "origin", null, IdentityZoneHolder.get().getId());
        prompts = new LinkedList<>();
        prompts.add(new Prompt("username", "text", "Email"));
        prompts.add(new Prompt("password", "password", "Password"));
        prompts.add(new Prompt("passcode", "text", "Temporary Authentication Code ( Get one at " + HTTP_LOCALHOST_8080_UAA + "/passcode )"));
        mockSamlIdentityProviderConfigurator = mock(SamlIdentityProviderConfigurator.class);
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions()).thenReturn(emptyList());
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitionsForZone(any())).thenReturn(emptyList());
        mockIdentityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        uaaIdentityProvider = new IdentityProvider();
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(eq(OriginKeys.UAA), anyString())).thenReturn(uaaIdentityProvider);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(eq(OriginKeys.LDAP), anyString())).thenReturn(new IdentityProvider());
        idps = getIdps();
        originalConfiguration = IdentityZoneHolder.get().getConfig();
        OidcMetadataFetcher mockOidcMetadataFetcher = mock(OidcMetadataFetcher.class);
        IdentityZoneHolder.get().setConfig(new IdentityZoneConfiguration());
        configurator = new XOAuthProviderConfigurator(mockIdentityProviderProvisioning, mockOidcMetadataFetcher);
        spiedMfaChecker = spy(new MfaChecker(mock(IdentityZoneProvisioning.class)));
        extendedModelMap = new ExtendedModelMap();
    }

    @AfterEach
    void clearZoneHolder() {
        IdentityZoneHolder.clear();
        IdentityZoneHolder.get().setConfig(originalConfiguration);
    }

    @Test
    void loginReturnsSystemZone() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertFalse(extendedModelMap.containsAttribute("zone_name"));
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));
        assertEquals(OriginKeys.UAA, extendedModelMap.asMap().get("zone_name"));
    }

    @Test
    void alreadyLoggedInRedirectsToHome() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        UaaAuthentication authentication = mock(UaaAuthentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        String result = endpoint.loginForHtml(extendedModelMap, authentication, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));
        assertEquals("redirect:/home", result);
    }

    @Test
    void deleteSavedAccount() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String userId = "testUserId";
        String result = endpoint.deleteSavedAccount(request, response, userId);
        Cookie[] cookies = response.getCookies();
        assertEquals(cookies.length, 1);
        assertEquals(cookies[0].getName(), "Saved-Account-" + userId);
        assertEquals(cookies[0].getMaxAge(), 0);
        assertEquals("redirect:/login", result);
    }

    @Test
    void savedAccountsPopulatedOnModel() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThat(extendedModelMap, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");

        Cookie cookie1 = new Cookie("Saved-Account-xxxx", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        savedAccount.setUsername("tim");
        savedAccount.setEmail("tim@example.org");
        savedAccount.setUserId("zzzz");
        savedAccount.setOrigin("ldap");
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        request.setCookies(cookie1, cookie2);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap, hasKey("savedAccounts"));
        assertThat(extendedModelMap.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) extendedModelMap.get("savedAccounts");
        assertThat(savedAccounts, hasSize(2));

        SavedAccountOption savedAccount0 = savedAccounts.get(0);
        assertThat(savedAccount0, notNullValue());
        assertEquals("bob", savedAccount0.getUsername());
        assertEquals("bob@example.com", savedAccount0.getEmail());
        assertEquals("uaa", savedAccount0.getOrigin());
        assertEquals("xxxx", savedAccount0.getUserId());

        SavedAccountOption savedAccount1 = savedAccounts.get(1);
        assertThat(savedAccount1, notNullValue());
        assertEquals("tim", savedAccount1.getUsername());
        assertEquals("tim@example.org", savedAccount1.getEmail());
        assertEquals("ldap", savedAccount1.getOrigin());
        assertEquals("zzzz", savedAccount1.getUserId());
    }

    @Test
    void ignoresBadJsonSavedAccount() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThat(extendedModelMap, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");
        Cookie cookieGood = new Cookie("Saved-Account-xxxx", JsonUtils.writeValueAsString(savedAccount));

        Cookie cookieBadJson = new Cookie("Saved-Account-Bad", "{");

        request.setCookies(cookieGood, cookieBadJson);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap, hasKey("savedAccounts"));
        assertThat(extendedModelMap.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) extendedModelMap.get("savedAccounts");
        assertThat(savedAccounts, hasSize(1));
    }

    @Test
    void savedAccountsEncodedAndUnEncoded() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThat(extendedModelMap, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bill");
        savedAccount.setEmail("bill@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");
        // write Cookie1 without URLencode into value, situation before this correction
        Cookie cookie1 = new Cookie("Saved-Account-xxxx", JsonUtils.writeValueAsString(savedAccount));

        savedAccount.setUsername("bill");
        savedAccount.setEmail("bill@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");
        // write Cookie2 with URLencode into value, situation after this correction
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8.name()));

        request.setCookies(cookie1, cookie2);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap, hasKey("savedAccounts"));
        assertThat(extendedModelMap.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) extendedModelMap.get("savedAccounts");
        assertThat(savedAccounts, hasSize(2));
        // evaluate that both cookies can be parsed out has have same values
        SavedAccountOption savedAccount0 = savedAccounts.get(0);
        assertThat(savedAccount0, notNullValue());
        assertEquals("bill", savedAccount0.getUsername());
        assertEquals("bill@example.com", savedAccount0.getEmail());
        assertEquals("uaa", savedAccount0.getOrigin());
        assertEquals("xxxx", savedAccount0.getUserId());

        SavedAccountOption savedAccount1 = savedAccounts.get(1);
        assertThat(savedAccount1, notNullValue());
        assertEquals("bill", savedAccount1.getUsername());
        assertEquals("bill@example.com", savedAccount1.getEmail());
        assertEquals("uaa", savedAccount1.getOrigin());
        assertEquals("xxxx", savedAccount1.getUserId());
    }

    @Test
    void savedAccountsInvalidCookie() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThat(extendedModelMap, not(hasKey("savedAccounts")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");

        Cookie cookie1 = new Cookie("Saved-Account-xxxx", "%2");

        request.setCookies(cookie1);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap, hasKey("savedAccounts"));
        assertThat(extendedModelMap.get("savedAccounts"), instanceOf(List.class));
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) extendedModelMap.get("savedAccounts");
        assertThat(savedAccounts, hasSize(0));
    }

    @Test
    void loginReturnsOtherZone() throws Exception {
        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        zone.setId("other-zone-id");
        zone.setSubdomain(zone.getName());
        IdentityZoneHolder.set(zone);
        LoginInfoEndpoint endpoint = getEndpoint(zone);
        assertFalse(extendedModelMap.containsAttribute("zone_name"));
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));
        assertEquals("some_other_zone", extendedModelMap.asMap().get("zone_name"));
    }

    @Test
    void customSelfserviceLinks_ApplyToAllZone_Html() throws Exception {
        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        zone.setId("some_id");
        zone.setSubdomain(zone.getName());
        IdentityZoneConfiguration config = zone.getConfig();
        IdentityZoneHolder.set(zone);
        zone.getConfig().getLinks().getSelfService().setSignup("http://custom_signup_link");
        zone.getConfig().getLinks().getSelfService().setPasswd("http://custom_passwd_link");
        LoginInfoEndpoint endpoint = getEndpoint(zone, DEFAULT_GLOBAL_LINKS);
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", extendedModelMap);
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", endpoint.getSelfServiceLinks());

        //null config
        zone.setConfig(null);
        validateSelfServiceLinks("/create_account", "/forgot_password", endpoint.getSelfServiceLinks());

        //null config with globals
        endpoint = getEndpoint(zone, new Links().setSelfService(new Links.SelfService().setSignup("/signup").setPasswd("/passwd")));
        validateSelfServiceLinks("/signup", "/passwd", endpoint.getSelfServiceLinks());

        //null links with globals
        IdentityZoneConfiguration otherConfig = new IdentityZoneConfiguration(null);
        otherConfig.getLinks().setSelfService(new Links.SelfService().setSignup(null).setPasswd(null));
        validateSelfServiceLinks("/signup", "/passwd", endpoint.getSelfServiceLinks());

        //null links with globals using variables
        endpoint = getEndpoint(zone, new Links().setSelfService(new Links.SelfService().setSignup("/signup?domain={zone.subdomain}").setPasswd("/passwd?id={zone.id}")));
        validateSelfServiceLinks("/signup?domain=" + zone.getSubdomain(), "/passwd?id=" + zone.getId(), endpoint.getSelfServiceLinks());

        //zone config overrides global
        zone.setConfig(config);
        validateSelfServiceLinks("http://custom_signup_link", "http://custom_passwd_link", endpoint.getSelfServiceLinks());

        //zone config supports variables too
        config.getLinks().getSelfService().setSignup("/local_signup?domain={zone.subdomain}");
        config.getLinks().getSelfService().setPasswd("/local_passwd?id={zone.id}");
        validateSelfServiceLinks("/local_signup?domain=" + zone.getSubdomain(), "/local_passwd?id=" + zone.getId(), endpoint.getSelfServiceLinks());
    }

    private static void validateSelfServiceLinks(
            final String signup,
            final String passwd,
            final Model model) {
        Map<String, String> links = (Map<String, String>) model.asMap().get("links");
        validateSelfServiceLinks(signup, passwd, links);
    }

    private static void validateSelfServiceLinks(
            final String signup,
            final String passwd,
            final Map<String, String> links) {
        assertEquals(signup, links.get("createAccountLink"));
        assertEquals(passwd, links.get("forgotPasswordLink"));
        //json links
        assertEquals(signup, links.get("register"));
        assertEquals(passwd, links.get("passwd"));
    }

    @Test
    void discoverIdentityProviderCarriesEmailIfProvided() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        endpoint.discoverIdentityProvider("testuser@fake.com", "true", null, extendedModelMap, session, request);

        assertEquals(extendedModelMap.get("email"), "testuser@fake.com");
    }

    @Test
    void discoverIdentityProviderCarriesLoginHintIfProvided() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        String loginHint = "{\"origin\":\"my-OIDC-idp1\"}";
        endpoint.discoverIdentityProvider("testuser@fake.com", "true", loginHint, extendedModelMap, session, request);

        assertEquals(loginHint, extendedModelMap.get("login_hint"));
    }

    @Test
    void discoverIdentityProviderWritesLoginHintIfOnlyUaa() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        UaaIdentityProviderDefinition uaaConfig = new UaaIdentityProviderDefinition();
        uaaConfig.setEmailDomain(singletonList("fake.com"));
        uaaIdentityProvider.setConfig(uaaConfig);
        uaaIdentityProvider.setType(OriginKeys.UAA);
        when(mockIdentityProviderProvisioning.retrieveActive("uaa")).thenReturn(singletonList(uaaIdentityProvider));

        endpoint.discoverIdentityProvider("testuser@fake.com", null, null, extendedModelMap, session, request);

        String loginHint = "{\"origin\":\"uaa\"}";
        assertEquals(loginHint, extendedModelMap.get("login_hint"));
    }

    @Test
    void use_login_url_if_present() {
        check_links_urls(IdentityZone.getUaa());
    }

    @Test
    void use_login_url_if_present_in_zone() {
        IdentityZone zone = MultitenancyFixture.identityZone("test", "test");
        check_links_urls(zone);
    }

    private void mfa_prompt(IdentityZone zone) {
        zone.getConfig().getMfaConfig().setEnabled(true);
        IdentityZoneHolder.set(zone);
        String baseUrl = check_links_urls(zone);
        Map mapPrompts = (Map) extendedModelMap.get("prompts");
        assertNotNull(mapPrompts.get("mfaCode"));
        assertEquals(
                "MFA Code ( Register at " + addSubdomainToUrl(baseUrl, IdentityZoneHolder.get().getSubdomain()) + " )",
                ((String[]) mapPrompts.get("mfaCode"))[1]
        );
    }

    @Test
    void mfa_prompt_in_default_zone() {
        IdentityZone zone = IdentityZone.getUaa();
        mfa_prompt(zone);
    }

    @Test
    void mfa_prompt_in_non_default_zone() {
        IdentityZone zone = MultitenancyFixture.identityZone("test", "test");
        mfa_prompt(zone);
    }

    private String check_links_urls(IdentityZone zone) {
        IdentityZoneHolder.set(zone);
        String baseUrl = "http://uaa.domain.com";
        LoginInfoEndpoint endpoint = getEndpoint(zone, null, baseUrl);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", baseUrl));
        assertEquals(addSubdomainToUrl(baseUrl, IdentityZoneHolder.get().getSubdomain()), ((Map<String, String>) extendedModelMap.asMap().get("links")).get("uaa"));
        assertEquals(addSubdomainToUrl(baseUrl.replace("uaa", "login"), IdentityZoneHolder.get().getSubdomain()), ((Map<String, String>) extendedModelMap.asMap().get("links")).get("login"));

        String loginBaseUrl = "http://external-login.domain.com";
        endpoint = getEndpoint(zone, loginBaseUrl, baseUrl);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", baseUrl));
        assertEquals(addSubdomainToUrl(baseUrl, IdentityZoneHolder.get().getSubdomain()), ((Map<String, String>) extendedModelMap.asMap().get("links")).get("uaa"));
        assertEquals(loginBaseUrl, ((Map<String, String>) extendedModelMap.asMap().get("links")).get("login"));

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(zone))).thenReturn(idps);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", baseUrl));
        Map mapPrompts = (Map) extendedModelMap.get("prompts");
        assertNotNull(mapPrompts.get("passcode"));
        assertEquals("Temporary Authentication Code ( Get one at " + addSubdomainToUrl(HTTP_LOCALHOST_8080_UAA, IdentityZoneHolder.get().getSubdomain()) + "/passcode )", ((String[]) mapPrompts.get("passcode"))[1]);
        return baseUrl;
    }

    @Test
    void no_self_service_links_if_self_service_disabled() {
        IdentityZone zone = MultitenancyFixture.identityZone("zone", "zone");
        zone.setConfig(new IdentityZoneConfiguration());
        zone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        IdentityZoneHolder.set(zone);
        LoginInfoEndpoint endpoint = getEndpoint(zone);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("register"));
        assertNull(links.get("passwd"));
    }

    @Test
    void no_ui_links_for_json() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("linkCreateAccountShow"));
        assertNull(links.get("fieldUsernameShow"));
        assertNull(links.get("forgotPasswordLink"));
        assertNull(links.get("createAccountLink"));
        assertEquals("http://someurl", links.get("login"));
        assertEquals("http://someurl", links.get("uaa"));
        assertEquals("/create_account", links.get("register"));
        assertEquals("/forgot_password", links.get("passwd"));
    }

    @Test
    void saml_links_for_json() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(any(), any())).thenReturn(idps);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertEquals("http://someurl", links.get("login"));
        assertTrue(extendedModelMap.get("idpDefinitions") instanceof Map);
        Map<String, String> idpDefinitions = (Map<String, String>) extendedModelMap.get("idpDefinitions");
        for (SamlIdentityProviderDefinition def : idps) {
            assertEquals(
                    "http://someurl/saml/discovery?returnIDParam=idp&entityID=" + endpoint.getZonifiedEntityId() + "&idp=" + def.getIdpEntityAlias() + "&isPassive=true",
                    idpDefinitions.get(def.getIdpEntityAlias())
            );
        }
    }

    @Test
    void saml_links_for_html() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"), null);
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertNotNull(links);
        assertEquals("http://someurl", links.get("login"));
        assertTrue(extendedModelMap.get("idpDefinitions") instanceof Collection);
    }

    @Test
    void no_self_service_links_if_internal_user_management_disabled() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        UaaIdentityProviderDefinition uaaIdentityProviderDefinition = new UaaIdentityProviderDefinition();
        uaaIdentityProviderDefinition.setDisableInternalUserManagement(true);
        uaaIdentityProvider.setConfig(uaaIdentityProviderDefinition);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertNotNull(links);
        assertNull(links.get("register"));
        assertNull(links.get("passwd"));
        assertNull(links.get("createAccountLink"));
        assertNull(links.get("forgotPasswordLink"));
        assertNull(extendedModelMap.asMap().get("createAccountLink"));
        assertNull(extendedModelMap.asMap().get("forgotPasswordLink"));
    }

    @Test
    void no_usernamePasswordBoxes_if_internalAuth_and_ldap_disabled() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(anyList(), any())).thenReturn(idps);

        IdentityProvider ldapIdentityProvider = new IdentityProvider();
        ldapIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, "uaa")).thenReturn(ldapIdentityProvider);

        IdentityProvider uaaIdentityProvider = new IdentityProvider();
        uaaIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, "uaa")).thenReturn(uaaIdentityProvider);


        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"), null);
        assertFalse((Boolean) extendedModelMap.get("fieldUsernameShow"));
    }

    @Test
    void generatePasscodeForKnownUaaPrincipal() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        Map<String, Object> model = new HashMap<>();
        assertEquals("passcode", endpoint.generatePasscode(model, marissa));
        UaaAuthentication uaaAuthentication = new UaaAuthentication(marissa, new ArrayList<>(), new UaaAuthenticationDetails(new MockHttpServletRequest()));
        assertEquals("passcode", endpoint.generatePasscode(model, uaaAuthentication));
        ExpiringUsernameAuthenticationToken expiringUsernameAuthenticationToken = new ExpiringUsernameAuthenticationToken(marissa, "");
        UaaAuthentication samlAuthenticationToken = new LoginSamlAuthenticationToken(marissa, expiringUsernameAuthenticationToken).getUaaAuthentication(emptyList(), emptySet(), new LinkedMultiValueMap<>());
        assertEquals("passcode", endpoint.generatePasscode(model, samlAuthenticationToken));
        //token with a UaaPrincipal should always work
        assertEquals("passcode", endpoint.generatePasscode(model, expiringUsernameAuthenticationToken));
    }

    @Test
    void generatePasscodeForUnknownUaaPrincipal() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        Map<String, Object> model = new HashMap<>();
        ExpiringUsernameAuthenticationToken token = new ExpiringUsernameAuthenticationToken("princpal", "");
        assertThrows(LoginInfoEndpoint.UnknownPrincipalException.class, () -> endpoint.generatePasscode(model, token));
    }

    @Test
    void promptLogic() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true);
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"), singletonList(MediaType.TEXT_HTML));
        assertNotNull("prompts attribute should be present", extendedModelMap.get("prompts"));
        assertTrue("prompts should be a Map for Html content", extendedModelMap.get("prompts") instanceof Map);
        Map mapPrompts = (Map) extendedModelMap.get("prompts");
        assertEquals("there should be two prompts for html", 2, mapPrompts.size());
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNull(mapPrompts.get("passcode"));
        assertNull(mapPrompts.get("mfaCode"));

        extendedModelMap.clear();
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        assertNotNull("prompts attribute should be present", extendedModelMap.get("prompts"));
        assertTrue("prompts should be a Map for JSON content", extendedModelMap.get("prompts") instanceof Map);
        mapPrompts = (Map) extendedModelMap.get("prompts");
        assertEquals("there should be two prompts for html", 3, mapPrompts.size());
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNotNull(mapPrompts.get("mfaCode"));
        assertNull(mapPrompts.get("passcode"));

        //add a SAML IDP, should make the passcode prompt appear
        extendedModelMap.clear();
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        assertNotNull("prompts attribute should be present", extendedModelMap.get("prompts"));
        assertTrue("prompts should be a Map for JSON content", extendedModelMap.get("prompts") instanceof Map);
        mapPrompts = (Map) extendedModelMap.get("prompts");
        assertEquals("there should be three prompts for html", 4, mapPrompts.size());
        assertNotNull(mapPrompts.get("username"));
        assertNotNull(mapPrompts.get("password"));
        assertNotNull(mapPrompts.get("passcode"));
        assertNotNull(mapPrompts.get("mfaCode"));

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        IdentityProvider ldapIdentityProvider = new IdentityProvider();
        ldapIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, "uaa")).thenReturn(ldapIdentityProvider);

        IdentityProvider uaaIdentityProvider = new IdentityProvider();
        uaaIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, "uaa")).thenReturn(uaaIdentityProvider);

        extendedModelMap.clear();
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        assertNotNull("prompts attribute should be present", extendedModelMap.get("prompts"));
        mapPrompts = (Map) extendedModelMap.get("prompts");
        assertNull(mapPrompts.get("username"));
        assertNull(mapPrompts.get("password"));
        assertNotNull(mapPrompts.get("passcode"));
    }

    @Test
    void filterIdpsForDefaultZone() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        // mock session and saved request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl()).thenReturn("http://localhost:8080/uaa");
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        request.setSession(session);
        // mock SamlIdentityProviderConfigurator
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) extendedModelMap.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        Iterator<SamlIdentityProviderDefinition> iterator = idpDefinitions.iterator();
        SamlIdentityProviderDefinition clientIdp = iterator.next();
        assertEquals("awesome-idp", clientIdp.getIdpEntityAlias());
        assertTrue(clientIdp.isShowSamlLink());

        clientIdp = iterator.next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertTrue(clientIdp.isShowSamlLink());
        assertEquals(true, extendedModelMap.asMap().get("fieldUsernameShow"));
        assertEquals(true, extendedModelMap.asMap().get("linkCreateAccountShow"));
    }

    @Test
    void filterIdpsWithNoSavedRequest() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions((List<String>) isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) extendedModelMap.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        Iterator<SamlIdentityProviderDefinition> iterator = idpDefinitions.iterator();
        SamlIdentityProviderDefinition clientIdp = iterator.next();
        assertEquals("awesome-idp", clientIdp.getIdpEntityAlias());
        assertTrue(clientIdp.isShowSamlLink());

        clientIdp = iterator.next();
        assertEquals("my-client-awesome-idp", clientIdp.getIdpEntityAlias());
        assertTrue(clientIdp.isShowSamlLink());
        assertEquals(true, extendedModelMap.asMap().get("fieldUsernameShow"));
        assertEquals(true, extendedModelMap.asMap().get("linkCreateAccountShow"));
    }

    @Test
    void filterIDPsForAuthcodeClientInDefaultZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-client-awesome-idp1", "my-client-awesome-idp2", OriginKeys.LDAP);

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        // mock SamlIdentityProviderConfigurator
        List<SamlIdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp1", "uaa"));
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp2", "uaa"));
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(eq(allowedProviders), eq(IdentityZone.getUaa()))).thenReturn(clientIDPs);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) extendedModelMap.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        assertThat(idpDefinitions, PredicateMatcher.has(c -> c.getIdpEntityAlias().equals("my-client-awesome-idp1")));
        assertThat(idpDefinitions, PredicateMatcher.has(c -> c.isShowSamlLink()));
        assertEquals(true, extendedModelMap.asMap().get("fieldUsernameShow"));
        assertEquals(false, extendedModelMap.asMap().get("linkCreateAccountShow"));
    }

    @Test
    void filterIDPsForAuthcodeClientInOtherZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        IdentityZone zone = MultitenancyFixture.identityZone("other-zone", "other-zone");
        IdentityZoneHolder.set(zone);

        List<String> allowedProviders = Arrays.asList("my-client-awesome-idp1", "my-client-awesome-idp2");

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "other-zone")).thenReturn(clientDetails);

        // mock SamlIdentityProviderConfigurator
        List<SamlIdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp1", "uaa"));
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp2", "uaa"));
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(eq(allowedProviders), eq(zone))).thenReturn(clientIDPs);


        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) extendedModelMap.asMap().get("idpDefinitions");
        assertEquals(2, idpDefinitions.size());

        assertThat(idpDefinitions, PredicateMatcher.has(c -> c.getIdpEntityAlias().equals("my-client-awesome-idp1")));
        assertThat(idpDefinitions, PredicateMatcher.has(SamlIdentityProviderDefinition::isShowSamlLink));
        assertEquals(false, extendedModelMap.asMap().get("fieldUsernameShow"));
        assertEquals(false, extendedModelMap.asMap().get("linkCreateAccountShow"));
    }

    @Test
    void filterIDPsForAuthcodeClientWithNoAllowedIDPsInOtherZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId(eq("client-id"), anyString())).thenReturn(clientDetails);

        IdentityZone zone = MultitenancyFixture.identityZone("other-zone", "other-zone");
        IdentityZoneHolder.set(zone);

        LoginInfoEndpoint endpoint = getEndpoint(zone, clientDetailsService);
        // mock SamlIdentityProviderConfigurator
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));
        verify(mockSamlIdentityProviderConfigurator).getIdentityProviderDefinitions(null, zone);
    }

    @Test
    void allowedIdpsforClientOIDCProvider() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2", OriginKeys.LDAP);

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        List<IdentityProvider> clientAllowedIdps = new LinkedList<>();
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp1"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp2"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp3"));

        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(clientAllowedIdps);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        Map<String, AbstractXOAuthIdentityProviderDefinition> idpDefinitions = (Map<String, AbstractXOAuthIdentityProviderDefinition>) extendedModelMap.asMap().get("oauthLinks");
        assertEquals(2, idpDefinitions.size());
    }

    @Test
    void oauth_provider_links_shown() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        RawXOAuthIdentityProviderDefinition definition = new RawXOAuthIdentityProviderDefinition();

        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        identityProvider.setConfig(definition);

        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), anyString())).thenReturn(singletonList(identityProvider));
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap.get("showLoginLinks"), equalTo(true));
    }

    @Test
    void passcode_prompt_present_whenThereIsAtleastOneActiveOauthProvider() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        RawXOAuthIdentityProviderDefinition definition = new RawXOAuthIdentityProviderDefinition()
                .setAuthUrl(new URL("http://auth.url"))
                .setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        identityProvider.setConfig(definition);

        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), anyString())).thenReturn(singletonList(identityProvider));
        endpoint.infoForLoginJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));

        Map mapPrompts = (Map) extendedModelMap.get("prompts");
        assertNotNull(mapPrompts.get("passcode"));
    }

    @Test
    void we_return_both_oauth_and_oidc_providers() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        RawXOAuthIdentityProviderDefinition oauthDefinition = new RawXOAuthIdentityProviderDefinition()
                .setAuthUrl(new URL("http://auth.url"))
                .setTokenUrl(new URL("http://token.url"));
        OIDCIdentityProviderDefinition oidcDefinition = new OIDCIdentityProviderDefinition()
                .setAuthUrl(new URL("http://auth.url"))
                .setTokenUrl(new URL("http://token.url"));

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oauthProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        oauthProvider.setConfig(oauthDefinition);

        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oidcProvider = MultitenancyFixture.identityProvider("oidc-idp-alias", "uaa");
        oidcProvider.setConfig(oidcDefinition);

        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), anyString())).thenReturn(Arrays.asList(oauthProvider, oidcProvider));
        assertEquals(2, endpoint.getOauthIdentityProviderDefinitions(null).size());
    }

    @Test
    void xoauthCallback_redirectsToHomeIfNoSavedRequest() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        HttpSession session = new MockHttpSession();
        String redirectUrl = endpoint.handleXOAuthCallback(session);
        assertEquals("redirect:/home", redirectUrl);
    }

    @Test
    void xoauthCallback_redirectsToSavedRequestIfPresent() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        HttpSession session = new MockHttpSession();
        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        when(savedRequest.getRedirectUrl()).thenReturn("/some.redirect.url");
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        String redirectUrl = endpoint.handleXOAuthCallback(session);
        assertEquals("redirect:/some.redirect.url", redirectUrl);
    }

    @Test
    void loginWithInvalidMediaType() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThrows(HttpMediaTypeNotAcceptableException.class,
                () -> endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_XML)));
    }

    @Test
    void generateAutologinCodeFailsWhenMfaRequired() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        doReturn(true).when(spiedMfaChecker).isMfaEnabled(any(IdentityZone.class));

        assertThrowsWithMessageThat(
                BadCredentialsException.class,
                () -> endpoint.generateAutologinCode(mock(AutologinRequest.class), "Basic 1234"),
                is("MFA is required")
        );
    }

    @Test
    void performAutologinFailsWhenMfaRequired() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        doReturn(true).when(spiedMfaChecker).isMfaEnabled(any(IdentityZone.class));

        assertThrowsWithMessageThat(
                BadCredentialsException.class,
                () -> endpoint.performAutologin(new MockHttpSession()),
                is("MFA is required")
        );
    }

    @Test
    void loginHintEmailDomain() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        IdentityProvider mockProvider = mock(IdentityProvider.class);
        when(mockProvider.getOriginKey()).thenReturn("my-OIDC-idp1");
        when(mockProvider.getType()).thenReturn(OriginKeys.OIDC10);
        AbstractXOAuthIdentityProviderDefinition mockOidcConfig = mock(OIDCIdentityProviderDefinition.class);
        when(mockOidcConfig.getAuthUrl()).thenReturn(new URL("http://localhost:8080/uaa"));
        when(mockOidcConfig.getRelyingPartyId()).thenReturn("client-id");
        when(mockOidcConfig.getResponseType()).thenReturn("token");
        when(mockOidcConfig.getEmailDomain()).thenReturn(singletonList("example.com"));
        when(mockProvider.getConfig()).thenReturn(mockOidcConfig);
        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), any())).thenReturn(singletonList(mockProvider));

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);


        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"example.com"});


        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
        assertNull(extendedModelMap.get("login_hint"));
    }

    @Test
    void loginHintOriginUaa() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});


        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", extendedModelMap.get("login_hint"));
    }

    @Test
    void loginHintOriginUaaDirectCall() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("login_hint", "{\"origin\":\"uaa\"}");

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", extendedModelMap.get("login_hint"));
    }

    @Test
    void loginHintOriginUaaDoubleEncoded() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{URLEncoder.encode("{\"origin\":\"uaa\"}", UTF_8)});


        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals(extendedModelMap.get("login_hint"), URLEncoder.encode("{\"origin\":\"uaa\"}", UTF_8));
    }

    @Test
    void loginHintOriginUaaAllowedProvidersNull() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, null);
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});


        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", extendedModelMap.get("login_hint"));
    }

    @Test
    void loginHintUaaNotAllowedLoginPageNotEmpty() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2");
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        List<IdentityProvider> clientAllowedIdps = new LinkedList<>();
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp1"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp2"));
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(clientAllowedIdps);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});


        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertNull(extendedModelMap.get("login_hint"));
        assertFalse((Boolean) extendedModelMap.get("fieldUsernameShow"));
        assertEquals("invalid_login_hint", extendedModelMap.get("error"));
    }

    @Test
    void loginHintOriginUaaSkipAccountChooser() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);


        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});

        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(true);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", extendedModelMap.get("login_hint"));
        assertEquals("idp_discovery/password", redirect);
    }

    @Test
    void invalidLoginHintErrorOnDiscoveryPage() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);


        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"invalidorigin\"}"});

        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(true);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(false);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("idp_discovery/email", redirect);
    }

    @Test
    void loginHintOriginOidc() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider(mockIdentityProviderProvisioning);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});


        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
        assertNull(extendedModelMap.get("login_hint"));
    }

    @Test
    void loginHintOriginOidcForJson() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider(mockIdentityProviderProvisioning);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});


        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertNotNull(extendedModelMap.get("prompts"));
        assertTrue(extendedModelMap.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertEquals(3, returnedPrompts.size());
    }

    @Test
    void loginHintOriginInvalid() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});


        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("invalid_login_hint", extendedModelMap.get("error"));
    }

    @Test
    void getPromptsFromOIDCProvider() {
        List<Prompt> customPrompts = new ArrayList<>();
        customPrompts.add(new Prompt("username", "text", "MyEmail"));
        customPrompts.add(new Prompt("password", "password", "MyPassword"));
        customPrompts.add(new Prompt("passcode", "text", "MyTemporary Authentication Code ( Get one at " + HTTP_LOCALHOST_8080_UAA + "/passcode )"));

        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("origin", "OIDC-without-prompts");
        IdentityProvider provider = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition oidcConfig = mock(OIDCIdentityProviderDefinition.class);

        when(oidcConfig.getPrompts()).thenReturn(customPrompts);
        when(provider.getConfig()).thenReturn(oidcConfig);
        when(mockIdentityProviderProvisioning.retrieveByOrigin("OIDC-without-prompts", "uaa")).thenReturn(provider);

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertNotNull(extendedModelMap.get("prompts"));
        assertTrue(extendedModelMap.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
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
        when(mockIdentityProviderProvisioning.retrieveByOrigin("non-OIDC", "uaa")).thenReturn(provider);

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);


        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertNotNull(extendedModelMap.get("prompts"));
        assertTrue(extendedModelMap.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
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
        when(mockIdentityProviderProvisioning.retrieveByOrigin("non-OIDC", "uaa")).thenThrow(mock(DataAccessException.class));

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);


        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertNotNull(extendedModelMap.get("prompts"));
        assertTrue(extendedModelMap.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
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
        when(mockIdentityProviderProvisioning.retrieveByOrigin("OIDC-without-prompts", "uaa")).thenReturn(provider);

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertNotNull(extendedModelMap.get("prompts"));
        assertTrue(extendedModelMap.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertEquals(2, returnedPrompts.size());

        assertNotNull(returnedPrompts.get("username"));
        assertEquals("Email", returnedPrompts.get("username")[1]);
        assertNotNull(returnedPrompts.get("password"));
        assertEquals("Password", returnedPrompts.get("password")[1]);
    }

    @Test
    void defaultProviderUaa() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("login", redirect);
        assertEquals("{\"origin\":\"uaa\"}", extendedModelMap.get("login_hint"));
    }

    @Test
    void defaultProviderOIDC() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("my-OIDC-idp1");

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);


        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
    }

    @Test
    void defaultProviderOIDCLoginForJson() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("my-OIDC-idp1");

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertNotNull(extendedModelMap.get("prompts"));
        assertTrue(extendedModelMap.get("prompts") instanceof Map);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertEquals(3, returnedPrompts.size());
    }

    @Test
    void defaultProviderBeforeDiscovery() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("my-OIDC-idp1");
        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(true);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        mockHttpServletRequest.setParameter("discoveryPerformed", "true");

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
    }

    @Test
    void loginHintOverridesDefaultProvider() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider(mockIdentityProviderProvisioning);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});


        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
        assertNull(extendedModelMap.get("login_hint"));
    }

    @Test
    void loginHintLdapOverridesDefaultProviderUaa() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = (SavedRequest) mockHttpServletRequest.getSession().getAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"ldap\"}"});

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"ldap\"}", extendedModelMap.get("login_hint"));
        assertEquals("login", redirect);
    }

    @Test
    void defaultProviderInvalidFallback() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("invalid");

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("login", redirect);
    }

    @Test
    void defaultProviderLdapWithAllowedOnlyOIDC() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = singletonList("my-OIDC-idp1");
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("ldap");

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);


        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect, startsWith("redirect:http://localhost:8080/uaa"));
        assertThat(redirect, containsString("my-OIDC-idp1"));
        assertFalse(extendedModelMap.containsKey("login_hint"));
    }

    @Test
    void allowedProvidersOnlyLDAPDoesNotUseInternalUsers() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = singletonList("ldap");
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"ldap\"}", extendedModelMap.get("login_hint"));
        assertEquals("login", redirect);
    }

    @Test
    void allowedProvidersLoginHintDoesKeepExternalProviders() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "uaa");
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        mockOidcProvider(mockIdentityProviderProvisioning);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertEquals("{\"origin\":\"uaa\"}", extendedModelMap.get("login_hint"));
        assertEquals("login", redirect);

        Map<String, String> oauthLinks = (Map<String, String>) extendedModelMap.get("oauthLinks");
        assertEquals(1, oauthLinks.size());
    }

    @Test
    void colorsMustBePublic() {
        final Function<String, Boolean> isPublic =
                (String str) -> {
                    try {
                        return Modifier.isPublic(LoginInfoEndpoint.SavedAccountOptionModel.class.getDeclaredField(str).getModifiers());
                    } catch (NoSuchFieldException e) {
                        return false;
                    }
                };

        assertEquals(Boolean.TRUE, isPublic.apply("red"));
        assertEquals(Boolean.TRUE, isPublic.apply("green"));
        assertEquals(Boolean.TRUE, isPublic.apply("blue"));
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

    private LoginInfoEndpoint getEndpoint(
            final IdentityZone identityZone,
            final String externalLoginUrl,
            final String baseUrl,
            final Links globalLinks,
            final MultitenantClientServices clientDetailsService) {
        LoginInfoEndpoint endpoint = new LoginInfoEndpoint(
                null,
                new InMemoryExpiringCodeStore(),
                externalLoginUrl,
                baseUrl,
                spiedMfaChecker,
                configurator,
                mockIdentityProviderProvisioning,
                "",
                globalLinks,
                clientDetailsService,
                mockSamlIdentityProviderConfigurator);
        if(identityZone.getConfig() != null) {
            identityZone.getConfig().setPrompts(prompts);
        }
        return endpoint;
    }

    private LoginInfoEndpoint getEndpoint(
            final IdentityZone identityZone,
            final String externalLoginUrl,
            final String baseUrl) {
        return getEndpoint(identityZone, externalLoginUrl, baseUrl, DEFAULT_GLOBAL_LINKS, null);
    }

    private LoginInfoEndpoint getEndpoint(
            final IdentityZone identityZone,
            final Links globalLinks) {
        return getEndpoint(identityZone, null, "http://someurl", globalLinks, null);
    }

    private LoginInfoEndpoint getEndpoint(final IdentityZone identityZone) {
        return getEndpoint(identityZone, (MultitenantClientServices) null);
    }

    private LoginInfoEndpoint getEndpoint(
            final IdentityZone identityZone,
            final MultitenantClientServices clientDetailsService) {
        return getEndpoint(identityZone,
                null,
                "http://someurl",
                DEFAULT_GLOBAL_LINKS,
                clientDetailsService);
    }

    private static List<SamlIdentityProviderDefinition> getIdps() {
        List<SamlIdentityProviderDefinition> idps = new LinkedList<>();
        idps.add(createIdentityProviderDefinition("awesome-idp", "uaa"));
        idps.add(createIdentityProviderDefinition("my-client-awesome-idp", "uaa"));
        return idps;
    }

    private static SamlIdentityProviderDefinition createIdentityProviderDefinition(String idpEntityAlias, String zoneId) {
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

    private static IdentityProvider createOIDCIdentityProvider(String originKey) throws MalformedURLException {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> oidcIdentityProvider = new IdentityProvider<>();
        oidcIdentityProvider.setOriginKey(originKey);
        oidcIdentityProvider.setType(OriginKeys.OIDC10);
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("https://" + originKey + ".com"));
        oidcIdentityProvider.setConfig(definition);

        return oidcIdentityProvider;
    }

    private static MultitenantClientServices mockClientService() {
        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2", OriginKeys.LDAP, OriginKeys.UAA);
        // mock Client service
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);
        return clientDetailsService;
    }

    private static void mockOidcProvider(IdentityProviderProvisioning mockIdentityProviderProvisioning) throws MalformedURLException {
        IdentityProvider mockProvider = mock(IdentityProvider.class);
        when(mockProvider.getOriginKey()).thenReturn("my-OIDC-idp1");
        when(mockProvider.getType()).thenReturn(OriginKeys.OIDC10);
        AbstractXOAuthIdentityProviderDefinition mockOidcConfig = mock(OIDCIdentityProviderDefinition.class);
        when(mockOidcConfig.getAuthUrl()).thenReturn(new URL("http://localhost:8080/uaa"));
        when(mockOidcConfig.getRelyingPartyId()).thenReturn("client-id");
        when(mockOidcConfig.getResponseType()).thenReturn("token");
        when(mockProvider.getConfig()).thenReturn(mockOidcConfig);
        when(mockOidcConfig.isShowLinkText()).thenReturn(true);
        when(mockIdentityProviderProvisioning.retrieveAll(anyBoolean(), any())).thenReturn(singletonList(mockProvider));
    }
}
