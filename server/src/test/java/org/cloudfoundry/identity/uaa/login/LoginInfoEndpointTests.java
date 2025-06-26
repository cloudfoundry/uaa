package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaRandomStringUtil;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.web.HttpMediaTypeNotAcceptableException;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addSubdomainToUrl;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class LoginInfoEndpointTests {

    private static final String HTTP_LOCALHOST_8080_UAA = "http://localhost:8080/uaa";
    private static final Links DEFAULT_GLOBAL_LINKS = new Links().setSelfService(new Links.SelfService().setPasswd(null).setSignup(null));
    private List<Prompt> prompts;
    private ExtendedModelMap extendedModelMap;
    private SamlIdentityProviderConfigurator mockSamlIdentityProviderConfigurator;
    private List<SamlIdentityProviderDefinition> idps;
    private IdentityProviderProvisioning mockIdentityProviderProvisioning;
    private IdentityProvider<UaaIdentityProviderDefinition> uaaIdentityProvider;
    private IdentityZoneConfiguration originalConfiguration;
    private ExternalOAuthProviderConfigurator configurator;

    @BeforeEach
    void setUp() {
        IdentityZoneHolder.clear();
        prompts = new LinkedList<>();
        prompts.add(new Prompt("username", "text", "Email"));
        prompts.add(new Prompt("password", "password", "Password"));
        prompts.add(new Prompt("passcode", "text", "Temporary Authentication Code ( Get one at " + HTTP_LOCALHOST_8080_UAA + "/passcode )"));
        mockSamlIdentityProviderConfigurator = mock(SamlIdentityProviderConfigurator.class);
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions()).thenReturn(emptyList());
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitionsForZone(any())).thenReturn(emptyList());
        mockIdentityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        uaaIdentityProvider = new IdentityProvider<>();
        IdentityZoneProvisioning identityZoneProvisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneManager identityZoneManager = new IdentityZoneManagerImpl();
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(eq(OriginKeys.UAA), anyString())).thenReturn(uaaIdentityProvider);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(eq(OriginKeys.LDAP), anyString())).thenReturn(new IdentityProvider());
        idps = getIdps();
        originalConfiguration = IdentityZoneHolder.get().getConfig();
        OidcMetadataFetcher mockOidcMetadataFetcher = mock(OidcMetadataFetcher.class);
        IdentityZoneHolder.get().setConfig(new IdentityZoneConfiguration());
        UaaRandomStringUtil randomStringUtil = mock(UaaRandomStringUtil.class);
        when(randomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");
        configurator = new ExternalOAuthProviderConfigurator(mockIdentityProviderProvisioning, mockOidcMetadataFetcher, randomStringUtil, identityZoneProvisioning, identityZoneManager);
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
        assertThat(extendedModelMap.containsAttribute("zone_name")).isFalse();
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));
        assertThat(extendedModelMap.asMap()).containsEntry("zone_name", OriginKeys.UAA);
    }

    @Test
    void alreadyLoggedInRedirectsToHome() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        UaaAuthentication authentication = mock(UaaAuthentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        String result = endpoint.loginForHtml(extendedModelMap, authentication, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));
        assertThat(result).isEqualTo("redirect:/home");
    }

    @Test
    void deleteSavedAccount() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String userId = "testUserId";
        String result = endpoint.deleteSavedAccount(request, response, userId);
        Cookie[] cookies = response.getCookies();
        assertThat(cookies).hasSize(1);
        assertThat("Saved-Account-" + userId).isEqualTo(cookies[0].getName());
        assertThat(cookies[0].getMaxAge()).isZero();
        assertThat(result).isEqualTo("redirect:/login");
    }

    @Test
    void savedAccountsPopulatedOnModel() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThat(extendedModelMap).doesNotContainKey("savedAccounts");
        MockHttpServletRequest request = new MockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");

        Cookie cookie1 = new Cookie("Saved-Account-xxxx", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8));

        savedAccount.setUsername("tim");
        savedAccount.setEmail("tim@example.org");
        savedAccount.setUserId("zzzz");
        savedAccount.setOrigin("ldap");
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8));

        request.setCookies(cookie1, cookie2);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsKey("savedAccounts");
        assertThat(extendedModelMap.get("savedAccounts")).isInstanceOf(List.class);
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) extendedModelMap.get("savedAccounts");
        assertThat(savedAccounts).hasSize(2);

        SavedAccountOption savedAccount0 = savedAccounts.getFirst();
        assertThat(savedAccount0).isNotNull();
        assertThat(savedAccount0.getUsername()).isEqualTo("bob");
        assertThat(savedAccount0.getEmail()).isEqualTo("bob@example.com");
        assertThat(savedAccount0.getOrigin()).isEqualTo("uaa");
        assertThat(savedAccount0.getUserId()).isEqualTo("xxxx");

        SavedAccountOption savedAccount1 = savedAccounts.get(1);
        assertThat(savedAccount1).isNotNull();
        assertThat(savedAccount1.getUsername()).isEqualTo("tim");
        assertThat(savedAccount1.getEmail()).isEqualTo("tim@example.org");
        assertThat(savedAccount1.getOrigin()).isEqualTo("ldap");
        assertThat(savedAccount1.getUserId()).isEqualTo("zzzz");
    }

    @Test
    void ignoresBadJsonSavedAccount() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThat(extendedModelMap).doesNotContainKey("savedAccounts");
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

        assertThat(extendedModelMap).containsKey("savedAccounts");
        assertThat(extendedModelMap.get("savedAccounts")).isInstanceOf(List.class);
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) extendedModelMap.get("savedAccounts");
        assertThat(savedAccounts).hasSize(1);
    }

    @Test
    void savedAccountsEncodedAndUnEncoded() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThat(extendedModelMap).doesNotContainKey("savedAccounts");
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
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8));

        request.setCookies(cookie1, cookie2);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsKey("savedAccounts");
        assertThat(extendedModelMap.get("savedAccounts")).isInstanceOf(List.class);
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) extendedModelMap.get("savedAccounts");
        assertThat(savedAccounts).hasSize(2);
        // evaluate that both cookies can be parsed out has have same values
        SavedAccountOption savedAccount0 = savedAccounts.getFirst();
        assertThat(savedAccount0).isNotNull();
        assertThat(savedAccount0.getUsername()).isEqualTo("bill");
        assertThat(savedAccount0.getEmail()).isEqualTo("bill@example.com");
        assertThat(savedAccount0.getOrigin()).isEqualTo("uaa");
        assertThat(savedAccount0.getUserId()).isEqualTo("xxxx");

        SavedAccountOption savedAccount1 = savedAccounts.get(1);
        assertThat(savedAccount1).isNotNull();
        assertThat(savedAccount1.getUsername()).isEqualTo("bill");
        assertThat(savedAccount1.getEmail()).isEqualTo("bill@example.com");
        assertThat(savedAccount1.getOrigin()).isEqualTo("uaa");
        assertThat(savedAccount1.getUserId()).isEqualTo("xxxx");
    }

    @Test
    void savedAccountsInvalidCookie() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThat(extendedModelMap).doesNotContainKey("savedAccounts");
        MockHttpServletRequest request = new MockHttpServletRequest();
        Cookie cookie1 = new Cookie("Saved-Account-xxxx", "%2");

        request.setCookies(cookie1);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsKey("savedAccounts");
        assertThat(extendedModelMap.get("savedAccounts")).isInstanceOf(List.class);
        List<SavedAccountOption> savedAccounts = (List<SavedAccountOption>) extendedModelMap.get("savedAccounts");
        assertThat(savedAccounts).isEmpty();
    }

    @Test
    void loginReturnsOtherZone() throws Exception {
        IdentityZone zone = new IdentityZone();
        zone.setName("some_other_zone");
        zone.setId("other-zone-id");
        zone.setSubdomain(zone.getName());
        IdentityZoneHolder.set(zone);
        LoginInfoEndpoint endpoint = getEndpoint(zone);
        assertThat(extendedModelMap.containsAttribute("zone_name")).isFalse();
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));
        assertThat(extendedModelMap.asMap()).containsEntry("zone_name", "some_other_zone");
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
        assertThat(links).containsEntry("createAccountLink", signup)
                .containsEntry("forgotPasswordLink", passwd)
                //json links
                .containsEntry("register", signup)
                .containsEntry("passwd", passwd);
    }

    @Test
    void discoverIdentityProviderCarriesEmailIfProvided() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        endpoint.discoverIdentityProvider("testuser@fake.com", "true", null, null, extendedModelMap, session, request);

        assertThat(extendedModelMap).containsEntry("email", "testuser@fake.com");
    }

    @Test
    void discoverIdentityProviderCarriesLoginHintIfProvided() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        String loginHint = "{\"origin\":\"my-OIDC-idp1\"}";
        endpoint.discoverIdentityProvider("testuser@fake.com", "true", loginHint, null, extendedModelMap, session, request);

        assertThat(extendedModelMap).containsEntry("login_hint", loginHint);
    }

    @Test
    void discoverIdentityProviderCarriesUsername() throws MalformedURLException {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("username", "testuser@fake.com");
        MockHttpSession session = new MockHttpSession();
        String loginHint = "{\"origin\":\"my-OIDC-idp1\"}";
        IdentityProvider idp = mock(IdentityProvider.class);
        OIDCIdentityProviderDefinition idpConfig = mock(OIDCIdentityProviderDefinition.class);
        when(idp.getType()).thenReturn(OriginKeys.OIDC10);
        when(idp.getOriginKey()).thenReturn("oidcOrigin");
        when(idpConfig.getEmailDomain()).thenReturn(Collections.singletonList("fake.com"));
        when(idpConfig.getAuthUrl()).thenReturn(URI.create("https://example.com/oauth/authorize").toURL());
        when(idpConfig.getResponseType()).thenReturn("code");
        when(idpConfig.getRelyingPartyId()).thenReturn("clientid");
        when(idpConfig.getRelyingPartySecret()).thenReturn("clientSecret");
        when(idpConfig.getUserPropagationParameter()).thenReturn("username");
        when(idp.getConfig()).thenReturn(idpConfig);
        when(mockIdentityProviderProvisioning.retrieveActive("uaa")).thenReturn(Collections.singletonList(idp));

        String redirect = endpoint.discoverIdentityProvider("testuser@fake.com", null, loginHint, "testuser@fake.com", extendedModelMap, session, request);

        assertThat(redirect).contains("username=testuser@fake.com");
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

        endpoint.discoverIdentityProvider("testuser@fake.com", null, null, null, extendedModelMap, session, request);

        String loginHint = "{\"origin\":\"uaa\"}";
        assertThat(extendedModelMap).containsEntry("login_hint", loginHint);
    }

    @Test
    void originChooserCarriesLoginHint() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        String redirect = endpoint.loginUsingOrigin("providedOrigin");

        assertThat(redirect).startsWith("redirect:/login?discoveryPerformed=true")
                .contains("login_hint")
                .contains("providedOrigin");
    }

    @Test
    void originChooserDefaultsToNoLoginHint() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        String redirect = endpoint.loginUsingOrigin(null);

        assertThat(redirect).isEqualTo("redirect:/login?discoveryPerformed=true");
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

    private String check_links_urls(IdentityZone zone) {
        IdentityZoneHolder.set(zone);
        String baseUrl = "http://uaa.domain.com";
        LoginInfoEndpoint endpoint = getEndpoint(zone, null, baseUrl);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", baseUrl));
        assertThat(((Map<String, String>) extendedModelMap.asMap().get("links"))).containsEntry("uaa", addSubdomainToUrl(baseUrl, IdentityZoneHolder.get().getSubdomain()))
                .containsEntry("login", addSubdomainToUrl(baseUrl.replace("uaa", "login"), IdentityZoneHolder.get().getSubdomain()));

        String loginBaseUrl = "http://external-login.domain.com";
        endpoint = getEndpoint(zone, loginBaseUrl, baseUrl);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", baseUrl));
        assertThat(((Map<String, String>) extendedModelMap.asMap().get("links")))
                .containsEntry("uaa", addSubdomainToUrl(baseUrl, IdentityZoneHolder.get().getSubdomain()))
                .containsEntry("login", loginBaseUrl);

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(isNull(), eq(zone))).thenReturn(idps);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", baseUrl));
        Map<String, Object> mapPrompts = (Map<String, Object>) extendedModelMap.get("prompts");
        assertThat(mapPrompts).containsKey("passcode");
        assertThat(((String[]) mapPrompts.get("passcode"))[1]).isEqualTo("Temporary Authentication Code ( Get one at " + addSubdomainToUrl(HTTP_LOCALHOST_8080_UAA, IdentityZoneHolder.get().getSubdomain()) + "/passcode )");
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
        assertThat(links).isNotNull()
                .doesNotContainKey("register")
                .doesNotContainKey("passwd");
    }

    @Test
    void no_ui_links_for_json() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertThat(links).isNotNull()
                .doesNotContainKey("linkCreateAccountShow")
                .doesNotContainKey("fieldUsernameShow")
                .doesNotContainKey("forgotPasswordLink")
                .doesNotContainKey("createAccountLink")
                .containsEntry("login", "http://someurl")
                .containsEntry("uaa", "http://someurl")
                .containsEntry("register", "/create_account")
                .containsEntry("passwd", "/forgot_password");
    }

    @Test
    void saml_links_for_json() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(any(), any())).thenReturn(idps);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertThat(links).containsEntry("login", "http://someurl");
        assertThat(extendedModelMap.get("idpDefinitions")).isInstanceOf(Map.class);
        Map<String, String> idpDefinitions = (Map<String, String>) extendedModelMap.get("idpDefinitions");

        var defs = idps.stream().collect(Collectors.toMap(SamlIdentityProviderDefinition::getIdpEntityAlias,
                def -> "http://someurl/saml2/authenticate/%s".formatted(def.getIdpEntityAlias())));
        assertThat(idpDefinitions).containsAllEntriesOf(defs);
    }

    @Test
    void saml_links_for_html() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"), null);
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertThat(links).isNotNull()
                .containsEntry("login", "http://someurl");
        assertThat(extendedModelMap.get("idpDefinitions")).isInstanceOf(Collection.class);
    }

    @Test
    void no_self_service_links_if_internal_user_management_disabled() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        UaaIdentityProviderDefinition uaaIdentityProviderDefinition = new UaaIdentityProviderDefinition();
        uaaIdentityProviderDefinition.setDisableInternalUserManagement(true);
        uaaIdentityProvider.setConfig(uaaIdentityProviderDefinition);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        Map<String, Object> links = (Map<String, Object>) extendedModelMap.asMap().get("links");
        assertThat(links).isNotNull()
                .doesNotContainKey("register")
                .doesNotContainKey("passwd")
                .doesNotContainKey("createAccountLink")
                .doesNotContainKey("forgotPasswordLink");
        assertThat(extendedModelMap.asMap())
                .doesNotContainKey("createAccountLink")
                .doesNotContainKey("forgotPasswordLink");
    }

    @Test
    void no_usernamePasswordBoxes_if_internalAuth_and_ldap_disabled() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(anyList(), any())).thenReturn(idps);

        IdentityProvider ldapIdentityProvider = new IdentityProvider();
        ldapIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, "uaa")).thenReturn(ldapIdentityProvider);

        IdentityProvider idp = new IdentityProvider();
        idp.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, "uaa")).thenReturn(idp);

        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"), null);
        assertThat((Boolean) extendedModelMap.get("fieldUsernameShow")).isFalse();
    }

    @Test
    void promptLogic() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"), singletonList(MediaType.TEXT_HTML));
        assertThat(extendedModelMap).as("prompts attribute should be present").containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).as("prompts should be a Map for Html content").isInstanceOf(Map.class);
        Map<String, Object> mapPrompts = (Map<String, Object>) extendedModelMap.get("prompts");
        assertThat(mapPrompts).as("there should be two prompts for html")
                .hasSize(2)
                .containsKey("username")
                .containsKey("password")
                .doesNotContainKey("passcode");

        extendedModelMap.clear();
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        assertThat(extendedModelMap).as("prompts attribute should be present").containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).as("prompts should be a Map for JSON content").isInstanceOf(Map.class);
        mapPrompts = (Map<String, Object>) extendedModelMap.get("prompts");
        assertThat(mapPrompts).as("there should be three prompts for html").hasSize(2)
                .containsKey("username")
                .containsKey("password")
                .doesNotContainKey("passcode");

        //add a SAML IDP
        extendedModelMap.clear();
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        assertThat(extendedModelMap).as("prompts attribute should be present").containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).as("prompts should be a Map for JSON content").isInstanceOf(Map.class);
        mapPrompts = (Map<String, Object>) extendedModelMap.get("prompts");
        assertThat(mapPrompts).as("there should be three prompts for html").hasSize(3)
                .containsKey("username")
                .containsKey("password")
                .containsKey("passcode");

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        IdentityProvider ldapIdentityProvider = new IdentityProvider();
        ldapIdentityProvider.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(OriginKeys.LDAP, "uaa")).thenReturn(ldapIdentityProvider);

        IdentityProvider idp = new IdentityProvider();
        idp.setActive(false);
        when(mockIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, "uaa")).thenReturn(idp);

        extendedModelMap.clear();
        endpoint.infoForJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));
        assertThat(extendedModelMap).as("prompts attribute should be present").containsKey("prompts");
        mapPrompts = (Map<String, Object>) extendedModelMap.get("prompts");
        assertThat(mapPrompts).doesNotContainKey("username")
                .doesNotContainKey("password")
                .containsKey("passcode");
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
        SessionUtils.setSavedRequestSession(session, savedRequest);
        request.setSession(session);
        // mock SamlIdentityProviderConfigurator
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) extendedModelMap.asMap().get("idpDefinitions");
        assertThat(idpDefinitions).hasSize(2);

        Iterator<SamlIdentityProviderDefinition> iterator = idpDefinitions.iterator();
        SamlIdentityProviderDefinition clientIdp = iterator.next();
        assertThat(clientIdp.getIdpEntityAlias()).isEqualTo("awesome-idp");
        assertThat(clientIdp.isShowSamlLink()).isTrue();

        clientIdp = iterator.next();
        assertThat(clientIdp.getIdpEntityAlias()).isEqualTo("my-client-awesome-idp");
        assertThat(clientIdp.isShowSamlLink()).isTrue();
        assertThat(extendedModelMap.asMap()).containsEntry("fieldUsernameShow", true)
                .containsEntry("linkCreateAccountShow", true);
    }

    @Test
    void filterIdpsWithNoSavedRequest() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(isNull(), eq(IdentityZone.getUaa()))).thenReturn(idps);

        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) extendedModelMap.asMap().get("idpDefinitions");
        assertThat(idpDefinitions).hasSize(2);

        Iterator<SamlIdentityProviderDefinition> iterator = idpDefinitions.iterator();
        SamlIdentityProviderDefinition clientIdp = iterator.next();
        assertThat(clientIdp.getIdpEntityAlias()).isEqualTo("awesome-idp");
        assertThat(clientIdp.isShowSamlLink()).isTrue();

        clientIdp = iterator.next();
        assertThat(clientIdp.getIdpEntityAlias()).isEqualTo("my-client-awesome-idp");
        assertThat(clientIdp.isShowSamlLink()).isTrue();
        assertThat(extendedModelMap.asMap()).containsEntry("fieldUsernameShow", true)
                .containsEntry("linkCreateAccountShow", true);
    }

    @Test
    void filterIDPsForAuthcodeClientInDefaultZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-client-awesome-idp1", "my-client-awesome-idp2", OriginKeys.LDAP);

        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        // mock SamlIdentityProviderConfigurator
        List<SamlIdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp1", "uaa"));
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp2", "uaa"));
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(allowedProviders, IdentityZone.getUaa())).thenReturn(clientIDPs);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) extendedModelMap.asMap().get("idpDefinitions");
        assertThat(idpDefinitions).hasSize(2);

        assertThat(idpDefinitions).extracting(SamlIdentityProviderDefinition::getIdpEntityAlias).contains("my-client-awesome-idp1");
        assertThat(idpDefinitions).extracting(SamlIdentityProviderDefinition::isShowSamlLink).contains(true);
        assertThat(extendedModelMap.asMap()).containsEntry("fieldUsernameShow", true)
                .containsEntry("linkCreateAccountShow", false);
    }

    @Test
    void filterIDPsForAuthcodeClientInOtherZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        IdentityZone zone = MultitenancyFixture.identityZone("other-zone", "other-zone");
        IdentityZoneHolder.set(zone);

        List<String> allowedProviders = Arrays.asList("my-client-awesome-idp1", "my-client-awesome-idp2");

        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "other-zone")).thenReturn(clientDetails);

        // mock SamlIdentityProviderConfigurator
        List<SamlIdentityProviderDefinition> clientIDPs = new LinkedList<>();
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp1", "uaa"));
        clientIDPs.add(createIdentityProviderDefinition("my-client-awesome-idp2", "uaa"));
        when(mockSamlIdentityProviderConfigurator.getIdentityProviderDefinitions(allowedProviders, zone)).thenReturn(clientIDPs);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        Collection<SamlIdentityProviderDefinition> idpDefinitions = (Collection<SamlIdentityProviderDefinition>) extendedModelMap.asMap().get("idpDefinitions");
        assertThat(idpDefinitions).hasSize(2);

        assertThat(idpDefinitions).extracting(SamlIdentityProviderDefinition::getIdpEntityAlias).contains("my-client-awesome-idp1");
        assertThat(idpDefinitions).extracting(SamlIdentityProviderDefinition::isShowSamlLink).contains(true);
        assertThat(extendedModelMap.asMap()).containsEntry("fieldUsernameShow", false)
                .containsEntry("linkCreateAccountShow", false);
    }

    @Test
    void authcodeWithAllowedProviderStillUsesAccountChooser() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        IdentityZone zone = MultitenancyFixture.identityZone("other-zone", "other-zone");
        zone.getConfig().setAccountChooserEnabled(true);
        zone.getConfig().setIdpDiscoveryEnabled(true);
        IdentityZoneHolder.set(zone);

        List<String> allowedProviders = Arrays.asList("uaa", "my-client-awesome-idp1");

        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "other-zone")).thenReturn(clientDetails);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).doesNotContainKey("login_hint");
    }

    @Test
    void filterIDPsForAuthcodeClientWithNoAllowedIDPsInOtherZone() throws Exception {
        // mock session and saved request
        MockHttpServletRequest request = getMockHttpServletRequest();

        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
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
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        List<IdentityProvider> clientAllowedIdps = new LinkedList<>();
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp3"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp2"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp1"));

        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), eq(OriginKeys.OIDC10), eq(OriginKeys.OAUTH20))).thenReturn(clientAllowedIdps);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        endpoint.loginForHtml(extendedModelMap, null, request, singletonList(MediaType.TEXT_HTML));

        Collection<Map<String, String>> idpDefinitions = (Collection<Map<String, String>>) extendedModelMap.asMap().get("oauthLinks");
        assertThat(idpDefinitions).hasSize(2);
        // Expect this always on top of list because of sorting
        assertThat(((Map.Entry<String, String>) idpDefinitions.iterator().next()).getValue()).isEqualTo("my-OIDC-idp1");
    }

    @Test
    void oauth_provider_links_shown() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        RawExternalOAuthIdentityProviderDefinition definition = new RawExternalOAuthIdentityProviderDefinition();

        definition.setAuthUrl(URI.create("http://auth.url").toURL());
        definition.setTokenUrl(URI.create("http://token.url").toURL());
        definition.setRelyingPartySecret("client-secret");

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        identityProvider.setConfig(definition);

        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), any(), any())).thenReturn(singletonList(identityProvider));
        endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_HTML));

        assertThat((Boolean) extendedModelMap.get("showLoginLinks")).isTrue();
    }

    @Test
    void no_passcode_prompt_present_whenThereIsAtleastOneActiveOauthProvider() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        RawExternalOAuthIdentityProviderDefinition definition = new RawExternalOAuthIdentityProviderDefinition()
                .setAuthUrl(URI.create("http://auth.url").toURL())
                .setTokenUrl(URI.create("http://token.url").toURL());

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        identityProvider.setConfig(definition);

        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), eq(OriginKeys.OIDC10), eq(OriginKeys.OAUTH20)))
                .thenReturn(singletonList(identityProvider));
        endpoint.infoForLoginJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));

        Map<String, Object> mapPrompts = (Map<String, Object>) extendedModelMap.get("prompts");
        assertThat(mapPrompts).doesNotContainKey("passcode");
    }

    @Test
    void no_passcode_prompt_present_whenThereIsAtleastOneActiveOauthProvider_stillWorksWithAccountChooser() throws Exception {
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        RawExternalOAuthIdentityProviderDefinition definition = new RawExternalOAuthIdentityProviderDefinition()
                .setAuthUrl(URI.create("http://auth.url").toURL())
                .setTokenUrl(URI.create("http://token.url").toURL());

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        identityProvider.setConfig(definition);

        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), eq(OriginKeys.OIDC10), eq(OriginKeys.OAUTH20)))
                .thenReturn(singletonList(identityProvider));
        endpoint.infoForLoginJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));

        Map<String, Object> mapPrompts = (Map<String, Object>) extendedModelMap.get("prompts");
        assertThat(mapPrompts).doesNotContainKey("passcode");
    }

    @Test
    void no_passcode_prompt_present_whenThereIsAtleastOneActiveOauthProvider_stillWorksWithDiscovery() throws Exception {
        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(true);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        RawExternalOAuthIdentityProviderDefinition definition = new RawExternalOAuthIdentityProviderDefinition()
                .setAuthUrl(URI.create("http://auth.url").toURL())
                .setTokenUrl(URI.create("http://token.url").toURL());

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        identityProvider.setConfig(definition);

        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), any())).thenReturn(singletonList(identityProvider));
        endpoint.infoForLoginJson(extendedModelMap, null, new MockHttpServletRequest("GET", "http://someurl"));

        Map<String, Object> mapPrompts = (Map<String, Object>) extendedModelMap.get("prompts");
        assertThat(mapPrompts).doesNotContainKey("passcode");
    }

    @Test
    void we_return_both_oauth_and_oidc_providers() throws Exception {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());

        RawExternalOAuthIdentityProviderDefinition oauthDefinition = new RawExternalOAuthIdentityProviderDefinition()
                .setAuthUrl(URI.create("http://auth.url").toURL())
                .setTokenUrl(URI.create("http://token.url").toURL());
        OIDCIdentityProviderDefinition oidcDefinition = new OIDCIdentityProviderDefinition()
                .setAuthUrl(URI.create("http://auth.url").toURL())
                .setTokenUrl(URI.create("http://token.url").toURL());

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> oauthProvider = MultitenancyFixture.identityProvider("oauth-idp-alias", "uaa");
        oauthProvider.setConfig(oauthDefinition);

        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> oidcProvider = MultitenancyFixture.identityProvider("oidc-idp-alias", "uaa");
        oidcProvider.setConfig(oidcDefinition);

        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), eq(OriginKeys.OIDC10), eq(OriginKeys.OAUTH20)))
                .thenReturn(Arrays.asList(oauthProvider, oidcProvider));
        assertThat(endpoint.getOauthIdentityProviderDefinitions(null)).hasSize(2);
    }

    @Test
    void externalOAuthCallback_redirectsToHomeIfNoSavedRequest() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        HttpSession session = new MockHttpSession();
        String redirectUrl = endpoint.handleExternalOAuthCallback(session, "origin");
        assertThat(redirectUrl).isEqualTo("redirect:/home");
    }

    @Test
    void externalOAuthCallback_redirectsToSavedRequestIfPresent() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        HttpSession session = new MockHttpSession();
        DefaultSavedRequest savedRequest = mock(DefaultSavedRequest.class);
        when(savedRequest.getRedirectUrl()).thenReturn("/some.redirect.url");
        SessionUtils.setSavedRequestSession(session, savedRequest);
        String redirectUrl = endpoint.handleExternalOAuthCallback(session, "origin");
        assertThat(redirectUrl).isEqualTo("redirect:/some.redirect.url");
    }

    @Test
    void loginWithInvalidMediaType() {
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get());
        assertThatExceptionOfType(HttpMediaTypeNotAcceptableException.class).isThrownBy(() -> endpoint.loginForHtml(extendedModelMap, null, new MockHttpServletRequest(), singletonList(MediaType.TEXT_XML)));
    }

    @Test
    void loginHintEmailDomain() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        IdentityProvider mockProvider = mock(IdentityProvider.class);
        when(mockProvider.getOriginKey()).thenReturn("my-OIDC-idp1");
        when(mockProvider.getType()).thenReturn(OriginKeys.OIDC10);
        AbstractExternalOAuthIdentityProviderDefinition mockOidcConfig = mock(OIDCIdentityProviderDefinition.class);
        when(mockOidcConfig.getAuthUrl()).thenReturn(URI.create("http://localhost:8080/uaa").toURL());
        when(mockOidcConfig.getRelyingPartyId()).thenReturn("client-id");
        when(mockOidcConfig.getRelyingPartySecret()).thenReturn("client-secret");
        when(mockOidcConfig.getResponseType()).thenReturn("token");
        when(mockOidcConfig.getEmailDomain()).thenReturn(singletonList("example.com"));
        when(mockProvider.getConfig()).thenReturn(mockOidcConfig);
        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), eq(OriginKeys.OIDC10), eq(OriginKeys.OAUTH20)))
                .thenReturn(singletonList(mockProvider));

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"example.com"});
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).startsWith("redirect:http://localhost:8080/uaa")
                .contains("my-OIDC-idp1");
        assertThat(extendedModelMap).doesNotContainKey("login_hint");
    }

    @Test
    void loginHintOriginUaa() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});


        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"uaa\"}");
    }

    @Test
    void loginHintOriginUaa_onlyAccountChooser() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});

        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(false);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).isEqualTo("idp_discovery/password");
        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"uaa\"}");
    }

    @Test
    void loginHintOriginUaaDirectCall() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("login_hint", "{\"origin\":\"uaa\"}");

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"uaa\"}");
    }

    @Test
    void loginHintOriginUaaDoubleEncoded() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{URLEncoder.encode("{\"origin\":\"uaa\"}", UTF_8)});
        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(URLEncoder.encode("{\"origin\":\"uaa\"}", UTF_8)).isEqualTo(extendedModelMap.get("login_hint"));
    }

    @Test
    void loginHintOriginUaaAllowedProvidersNull() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, null);
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});


        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"uaa\"}");
    }

    @Test
    void loginHintUaaNotAllowedLoginPageNotEmpty() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2");
        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        List<IdentityProvider> clientAllowedIdps = new LinkedList<>();
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp1"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp2"));
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(clientAllowedIdps);

        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});


        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).doesNotContainKey("login_hint")
                .containsEntry("error", "invalid_login_hint")
                .containsEntry("fieldUsernameShow", false);
    }

    @Test
    void noLoginHintAccountChooser() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");
        Cookie cookie1 = new Cookie("Saved-Account-xxxx", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8));

        savedAccount.setUsername("tim");
        savedAccount.setEmail("tim@example.org");
        savedAccount.setUserId("zzzz");
        savedAccount.setOrigin("ldap");
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8));

        mockHttpServletRequest.setCookies(cookie1, cookie2);

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());

        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(true);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).isEqualTo("idp_discovery/account_chooser");
        verify(mockIdentityProviderProvisioning, times(0)).retrieveAll(eq(true), anyString());
        verify(mockSamlIdentityProviderConfigurator, times(0)).getIdentityProviderDefinitions(any(), any());
    }

    @Test
    void loginHintOriginUaaSkipAccountChooser() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        SavedAccountOption savedAccount = new SavedAccountOption();

        savedAccount.setUsername("bob");
        savedAccount.setEmail("bob@example.com");
        savedAccount.setUserId("xxxx");
        savedAccount.setOrigin("uaa");
        Cookie cookie1 = new Cookie("Saved-Account-xxxx", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8));

        savedAccount.setUsername("tim");
        savedAccount.setEmail("tim@example.org");
        savedAccount.setUserId("zzzz");
        savedAccount.setOrigin("ldap");
        Cookie cookie2 = new Cookie("Saved-Account-zzzz", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), UTF_8));
        mockHttpServletRequest.setCookies(cookie1, cookie2);

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());

        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"uaa\"}"});

        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(true);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"uaa\"}");
        assertThat(redirect).isEqualTo("idp_discovery/email");
    }

    @Test
    void invalidLoginHintErrorOnDiscoveryPage() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"invalidorigin\"}"});

        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(true);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(false);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).isEqualTo("idp_discovery/email");
    }

    @Test
    void invalidLoginHintErrorOnAccountChooserPage() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"invalidorigin\"}"});

        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(false);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).isEqualTo("idp_discovery/account_chooser");
        assertThat(extendedModelMap).containsKey("error");
    }

    @Test
    void invalidLoginHintLoginPageReturnsList() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        List<IdentityProvider> clientAllowedIdps = new LinkedList<>();
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp1"));
        clientAllowedIdps.add(createOIDCIdentityProvider("my-OIDC-idp2"));
        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), eq(OriginKeys.OIDC10), eq(OriginKeys.OAUTH20))).thenReturn(clientAllowedIdps);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(eq("invalidorigin"), anyString())).thenThrow(new EmptyResultDataAccessException(1));

        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"invalidorigin\"}"});
        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, Collections.singletonList(MediaType.TEXT_HTML));
        assertThat(((Collection<Map<String, String>>) extendedModelMap.get("oauthLinks"))).isNotEmpty();
    }

    @Test
    void loginHintOriginOidc() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        MultitenantClientServices clientDetailsService = mockClientService();
        mockLoginHintProvider(configurator);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).startsWith("redirect:http://localhost:8080/uaa")
                .contains("my-OIDC-idp1");
        assertThat(extendedModelMap).doesNotContainKey("login_hint");
    }

    @Test
    void loginHintOriginOidcForJson() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        MultitenantClientServices clientDetailsService = mockClientService();
        mockLoginHintProvider(configurator);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});
        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertThat(extendedModelMap).containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).isInstanceOf(Map.class);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertThat(returnedPrompts).hasSize(3);
    }

    @Test
    void loginHintOriginInvalid() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});
        when(configurator.retrieveByOrigin(eq("my-OIDC-idp1"), anyString())).thenThrow(new EmptyResultDataAccessException(0));

        endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));
        assertThat(extendedModelMap).containsEntry("error", "invalid_login_hint");
    }

    @Test
    void getPromptsFromOIDCProvider() {
        List<Prompt> customPrompts = new ArrayList<>();
        customPrompts.add(new Prompt("username", "text", "MyEmail"));
        customPrompts.add(new Prompt("password", "password", "MyPassword"));
        final String passcodePromptText = "MyTemporary Authentication Code ( Get one at %s/passcode )"
                .formatted(HTTP_LOCALHOST_8080_UAA);
        customPrompts.add(new Prompt("passcode", "text", passcodePromptText));

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

        assertThat(extendedModelMap).containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).isInstanceOf(Map.class);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertThat(returnedPrompts).hasSize(2)
                .containsKey("username")
                .containsKey("password")
                .doesNotContainKey("passcode");
        assertThat(returnedPrompts.get("username")[1]).isEqualTo("MyEmail");
        assertThat(returnedPrompts.get("password")[1]).isEqualTo("MyPassword");
        assertThat(returnedPrompts.get("passcode")).isNull();
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

        assertThat(extendedModelMap).containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).isInstanceOf(Map.class);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertUsernamePasswordButNoPasscodePromptsAreReturned(returnedPrompts);
    }

    @Test
    void getPromptsFromNonExistentProvider() {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        mockHttpServletRequest.setParameter("origin", "non-OIDC");
        when(mockIdentityProviderProvisioning.retrieveByOrigin("non-OIDC", "uaa")).thenThrow(mock(DataAccessException.class));

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertThat(extendedModelMap).containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).isInstanceOf(Map.class);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertUsernamePasswordButNoPasscodePromptsAreReturned(returnedPrompts);
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

        assertThat(extendedModelMap).containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).isInstanceOf(Map.class);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertUsernamePasswordButNoPasscodePromptsAreReturned(returnedPrompts);
    }

    @Test
    void defaultProviderUaa() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).isEqualTo("login");
        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"uaa\"}")
                .containsEntry("defaultIdpName", "uaa");
    }

    @Test
    void defaultProviderOIDC() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("my-OIDC-idp1");
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).startsWith("redirect:http://localhost:8080/uaa")
                .contains("my-OIDC-idp1");
    }

    @Test
    void defaultProviderOIDCLoginForJson() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        MultitenantClientServices clientDetailsService = mockClientService();

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("my-OIDC-idp1");

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        endpoint.infoForLoginJson(extendedModelMap, null, mockHttpServletRequest);

        assertThat(extendedModelMap).containsKey("prompts");
        assertThat(extendedModelMap.get("prompts")).isInstanceOf(Map.class);
        Map<String, String[]> returnedPrompts = (Map<String, String[]>) extendedModelMap.get("prompts");
        assertThat(returnedPrompts).hasSize(3);
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

        assertThat(redirect).startsWith("redirect:http://localhost:8080/uaa")
                .contains("my-OIDC-idp1");
    }

    @Test
    void discoveryPerformedWithAccountChooserOnlyReturnsLoginPage() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(false);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        mockHttpServletRequest.setParameter("discoveryPerformed", "true");
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).isEqualTo("idp_discovery/password");
    }

    @Test
    void discoveryPerformedWithAccountChooserOnlyReturnsDefaultIdp() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("my-OIDC-idp1");
        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(false);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        mockHttpServletRequest.setParameter("discoveryPerformed", "true");
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).startsWith("redirect:http://localhost:8080/uaa")
                .contains("my-OIDC-idp1");
    }

    @Test
    void accountChooserOnlyReturnsOriginChooser() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("my-OIDC-idp1");
        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(false);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);

        String oidcOrigin1 = "my-OIDC-idp1";
        String oidcOrigin2 = "my-OIDC-idp2"; //Test also non-default idp

        List<List<String>> idpCollections = List.of(
                List.of(OriginKeys.UAA, OriginKeys.LDAP, oidcOrigin1, oidcOrigin2),
                List.of(OriginKeys.UAA, oidcOrigin1, oidcOrigin2),
                List.of(OriginKeys.LDAP, oidcOrigin1, oidcOrigin2),
                List.of(OriginKeys.UAA, OriginKeys.LDAP, oidcOrigin1),
                List.of(OriginKeys.UAA, OriginKeys.LDAP, oidcOrigin2),
                List.of(oidcOrigin1, oidcOrigin2),
                List.of(oidcOrigin1),
                List.of(oidcOrigin2));

        for (List<String> idpCollection : idpCollections) {
            MultitenantClientServices clientDetailsService = mockClientService(idpCollection);
            LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);

            String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

            assertThat(redirect).isEqualTo("idp_discovery/origin");
            verify(mockIdentityProviderProvisioning, times(0)).retrieveAll(eq(true), anyString());
            verify(mockSamlIdentityProviderConfigurator, times(0)).getIdentityProviderDefinitions(any(), any());
        }
    }

    @Test
    void accountChooserOnlyReturnsOriginChooser_whenUsingNoAllowedProviders() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("my-OIDC-idp1");
        IdentityZoneHolder.get().getConfig().setIdpDiscoveryEnabled(false);
        IdentityZoneHolder.get().getConfig().setAccountChooserEnabled(true);

        MultitenantClientServices clientDetailsService = mockClientService(null);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).isEqualTo("idp_discovery/origin");
        verify(mockIdentityProviderProvisioning, times(0)).retrieveAll(eq(true), anyString());
        verify(mockSamlIdentityProviderConfigurator, times(0)).getIdentityProviderDefinitions(any(), any());
    }

    @Test
    void loginHintOverridesDefaultProvider() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
        MultitenantClientServices clientDetailsService = mockClientService();
        mockLoginHintProvider(configurator);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-OIDC-idp1\"}"});
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).startsWith("redirect:http://localhost:8080/uaa")
                .contains("my-OIDC-idp1");
        assertThat(extendedModelMap).doesNotContainKey("login_hint");
    }

    @Test
    void loginHintSamlOverridesDefaultProvider() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2", "my-client-awesome-idp", OriginKeys.LDAP, OriginKeys.UAA);
        MultitenantClientServices clientDetailsService = mockClientService(allowedProviders);
        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getType()).thenReturn(OriginKeys.SAML);
        when(idp.getOriginKey()).thenReturn("my-client-awesome-id");
        when(idp.getConfig()).thenReturn(mock(SamlIdentityProviderDefinition.class));
        when(mockIdentityProviderProvisioning.retrieveByOrigin(eq("my-client-awesome-idp"), any())).thenReturn(idp);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"my-client-awesome-idp\"}"});
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).startsWith("redirect:/saml2/authenticate/")
                .contains("saml2");
        assertThat(extendedModelMap).doesNotContainKey("login_hint");
    }

    @Test
    void loginHintLdapOverridesDefaultProviderUaa() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("uaa");
        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        SavedRequest savedRequest = SessionUtils.getSavedRequestSession(mockHttpServletRequest.getSession());
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"{\"origin\":\"ldap\"}"});
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"ldap\"}");
        assertThat(redirect).isEqualTo("login");
    }

    @Test
    void defaultProviderInvalidFallback() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("invalid");

        MultitenantClientServices clientDetailsService = mockClientService();
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).isEqualTo("login");
    }

    @Test
    void defaultProviderLdapWithAllowedOnlyOIDC() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();
        List<String> allowedProviders = singletonList("my-OIDC-idp1");
        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        mockOidcProvider(mockIdentityProviderProvisioning);
        IdentityZoneHolder.get().getConfig().setDefaultIdentityProvider("ldap");
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(redirect).startsWith("redirect:http://localhost:8080/uaa")
                .contains("my-OIDC-idp1");
        assertThat(extendedModelMap).doesNotContainKey("login_hint");
    }

    @Test
    void allowedProvidersOnlyLDAPDoesNotUseInternalUsers() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = singletonList("ldap");
        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"ldap\"}");
        assertThat(redirect).isEqualTo("login");
    }

    @Test
    void allowedProvidersLoginHintDoesKeepExternalProviders() throws Exception {
        MockHttpServletRequest mockHttpServletRequest = getMockHttpServletRequest();

        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "uaa");
        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);

        mockOidcProvider(mockIdentityProviderProvisioning);
        LoginInfoEndpoint endpoint = getEndpoint(IdentityZoneHolder.get(), clientDetailsService);
        String redirect = endpoint.loginForHtml(extendedModelMap, null, mockHttpServletRequest, singletonList(MediaType.TEXT_HTML));

        assertThat(extendedModelMap).containsEntry("login_hint", "{\"origin\":\"uaa\"}");
        assertThat(redirect).isEqualTo("login");

        Collection<Map<String, String>> oauthLinks = (Collection<Map<String, String>>) extendedModelMap.get("oauthLinks");
        assertThat(oauthLinks).hasSize(1);
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

        assertThat(isPublic.apply("red")).isTrue();
        assertThat(isPublic.apply("green")).isTrue();
        assertThat(isPublic.apply("blue")).isTrue();
    }

    private MockHttpServletRequest getMockHttpServletRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getParameterValues("client_id")).thenReturn(new String[]{"client-id"});
        when(savedRequest.getRedirectUrl())
                .thenReturn("http://localhost:8080/uaa/oauth/authorize?client_id=identity&redirect_uri=http%3A%2F%2Flocalhost%3A8888%2Flogin&response_type=code&state=8tp0tR");
        SessionUtils.setSavedRequestSession(session, savedRequest);
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
                new InMemoryExpiringCodeStore(new TimeServiceImpl()),
                externalLoginUrl,
                baseUrl,
                configurator,
                mockIdentityProviderProvisioning,
                "",
                globalLinks,
                clientDetailsService,
                mockSamlIdentityProviderConfigurator);
        if (identityZone.getConfig() != null) {
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
        IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> oidcIdentityProvider = new IdentityProvider<>();
        oidcIdentityProvider.setOriginKey(originKey);
        oidcIdentityProvider.setType(OriginKeys.OIDC10);
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(new URL("https://" + originKey + ".com"));
        definition.setRelyingPartySecret("client-secret");
        definition.setLinkText(originKey);
        oidcIdentityProvider.setConfig(definition);

        return oidcIdentityProvider;
    }

    private static MultitenantClientServices mockClientService() {
        List<String> allowedProviders = Arrays.asList("my-OIDC-idp1", "my-OIDC-idp2", OriginKeys.LDAP, OriginKeys.UAA);
        return mockClientService(allowedProviders);
    }

    private static MultitenantClientServices mockClientService(List<String> allowedProviders) {
        // mock Client service
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client-id");
        if (allowedProviders != null) {
            clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, new LinkedList<>(allowedProviders));
        }
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        when(clientDetailsService.loadClientByClientId("client-id", "uaa")).thenReturn(clientDetails);
        return clientDetailsService;
    }

    private static void mockOidcProvider(IdentityProviderProvisioning mockIdentityProviderProvisioning) throws MalformedURLException {
        IdentityProvider mockProvider = mock(IdentityProvider.class);
        when(mockProvider.getOriginKey()).thenReturn("my-OIDC-idp1");
        when(mockProvider.getType()).thenReturn(OriginKeys.OIDC10);
        AbstractExternalOAuthIdentityProviderDefinition mockOidcConfig = mock(OIDCIdentityProviderDefinition.class);
        when(mockOidcConfig.getAuthUrl()).thenReturn(URI.create("http://localhost:8080/uaa").toURL());
        when(mockOidcConfig.getRelyingPartyId()).thenReturn("client-id");
        when(mockOidcConfig.getRelyingPartySecret()).thenReturn("client-secret");
        when(mockOidcConfig.getResponseType()).thenReturn("token");
        when(mockProvider.getConfig()).thenReturn(mockOidcConfig);
        when(mockOidcConfig.isShowLinkText()).thenReturn(true);
        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), any())).thenReturn(singletonList(mockProvider));
        when(mockIdentityProviderProvisioning.retrieveActiveByTypes(anyString(), any(), any())).thenReturn(singletonList(mockProvider));
        when(mockIdentityProviderProvisioning.retrieveByOrigin(eq("my-OIDC-idp1"), any())).thenReturn(mockProvider);
    }

    private static void mockLoginHintProvider(ExternalOAuthProviderConfigurator mockIdentityProviderProvisioning)
            throws MalformedURLException {
        IdentityProvider mockProvider = mock(IdentityProvider.class);
        when(mockProvider.getOriginKey()).thenReturn("my-OIDC-idp1");
        when(mockProvider.getType()).thenReturn(OriginKeys.OIDC10);
        AbstractExternalOAuthIdentityProviderDefinition mockOidcConfig = mock(OIDCIdentityProviderDefinition.class);
        when(mockOidcConfig.getAuthUrl()).thenReturn(URI.create("http://localhost:8080/uaa").toURL());
        when(mockOidcConfig.getRelyingPartyId()).thenReturn("client-id");
        when(mockOidcConfig.getRelyingPartySecret()).thenReturn("client-secret");
        when(mockOidcConfig.getResponseType()).thenReturn("token");
        when(mockProvider.getConfig()).thenReturn(mockOidcConfig);
        when(mockOidcConfig.isShowLinkText()).thenReturn(true);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(eq("my-OIDC-idp1"), any())).thenReturn(mockProvider);
    }

    private static void assertUsernamePasswordButNoPasscodePromptsAreReturned(
            final Map<String, String[]> returnedPrompts
    ) {
        assertThat(returnedPrompts).hasSize(2)
                .containsKey("username")
                .containsKey("password")
                .doesNotContainKey("passcode");
        assertThat(returnedPrompts.get("username")[1]).isEqualTo("Email");
        assertThat(returnedPrompts.get("password")[1]).isEqualTo("Password");
        assertThat(returnedPrompts.get("passcode")).isNull();
    }
}
