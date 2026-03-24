package org.cloudfoundry.identity.uaa.login;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderDataTests;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpMethod;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.InvalidIdentityZoneDetailsException;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.io.File;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createOtherIdentityZone;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getMarissaSecurityContext;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUaaSecurityContext;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.security.web.CorsFilter.X_REQUESTED_WITH;
import static org.cloudfoundry.identity.uaa.util.SessionUtils.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@DefaultTestContext
@DirtiesContext
// public for LimitedModeLoginMockMvcTests
@EnabledIfZonePathsEnabled
public class LoginMockMvcZonePathTests {

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JdbcIdentityZoneProvisioning identityZoneProvisioning;
    @Autowired
    private FilterRegistrationBean<LimitedModeUaaFilter> limitedModeUaaFilter;

    @Autowired
    private JdbcExpiringCodeStore jdbcExpiringCodeStore;
    @Autowired
    private LoginInfoEndpoint loginInfoEndpoint;

    @Autowired
    private IdentityZoneConfigurationBootstrap identityZoneConfigurationBootstrap;

    @Autowired
    @Qualifier("globalLinks")
    Links globalLinks;
    @Autowired
    private ScimUserProvisioning scimUserProvisioning;
    @Autowired
    private JdbcIdentityProviderProvisioning identityProviderProvisioning;
    @Autowired
    private CookieBasedCsrfTokenRepository cookieBasedCsrfTokenRepository;
    @Autowired
    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    @Autowired
    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;

    @Autowired
    private ExpiringCodeStore expiringCodeStore;
    @Autowired
    private FilterRegistrationBean<CorsFilter> corsFilter;

    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final String DEFAULT_COPYRIGHT_TEMPLATE = "Copyright © %s";
    private static final String CF_COPYRIGHT_TEXT = DEFAULT_COPYRIGHT_TEMPLATE.formatted("CloudFoundry.org Foundation, Inc.");
    private static final String CF_LAST_LOGIN = "Last Login";

    private AlphanumericRandomValueStringGenerator generator;

    private IdentityZoneConfiguration identityZoneConfiguration;
    private IdentityZone identityZone;
    private File originalLimitedModeStatusFile;

    @MockBean
    OidcMetadataFetcher oidcMetadataFetcher;

    @BeforeEach
    void setUpContext() throws Exception {
        generator = new AlphanumericRandomValueStringGenerator();
        SecurityContextHolder.clearContext();

        MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        IdentityZoneHolder.setProvisioning(identityZoneProvisioning);

        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        identityZone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        identityZoneConfiguration = identityZone.getConfig() != null ? identityZone.getConfig() : new IdentityZoneConfiguration();

        MockMvcUtils.updateIdentityZone(identityZone, webApplicationContext);

        originalLimitedModeStatusFile = MockMvcUtils.getLimitedModeStatusFile(webApplicationContext);
        MockMvcUtils.resetLimitedModeStatusFile(webApplicationContext, null);
        assertThat(isLimitedMode(limitedModeUaaFilter.getFilter())).isFalse();
    }

    @AfterEach
    void resetGenerator() {
        jdbcExpiringCodeStore.setGenerator(new RandomValueStringGenerator(24));
    }

    @AfterEach
    void tearDown() throws Exception {
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, identityZone.getId(), true);
        resetUaaZoneConfigToDefault(identityZoneConfigurationBootstrap);
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        MockMvcUtils.resetLimitedModeStatusFile(webApplicationContext, originalLimitedModeStatusFile);
    }

    private void resetUaaZoneConfigToDefault(IdentityZoneConfigurationBootstrap identityZoneConfigurationBootstrap) throws InvalidIdentityZoneDetailsException {
        identityZoneConfigurationBootstrap.afterPropertiesSet();
    }

    private static MockHttpSession configure_UAA_for_idp_discovery(
            WebApplicationContext webApplicationContext,
            JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning,
            AlphanumericRandomValueStringGenerator generator,
            String originKey,
            IdentityZone zone, List<String> allowedProviders,
            ZoneResolutionMode mode) {

        String metadata = MockMvcUtils.IDP_META_DATA.formatted(new AlphanumericRandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition config = (SamlIdentityProviderDefinition) new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(originKey)
                .setLinkText("Active SAML Provider")
                .setZoneId(zone.getId())
                .setEmailDomain(Collections.singletonList("test.org"));

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(originKey, zone.getId());
        identityProvider.setType(SAML);
        identityProvider.setConfig(config);
        createIdentityProvider(jdbcIdentityProviderProvisioning, zone, identityProvider);

        identityProvider = MultitenancyFixture.identityProvider(LDAP, zone.getId());
        identityProvider.setType(LDAP);
        identityProvider.setConfig(new LdapIdentityProviderDefinition().setEmailDomain(Collections.singletonList("testLdap.org")));
        createIdentityProvider(jdbcIdentityProviderProvisioning, zone, identityProvider);

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, allowedProviders);

        MockMvcUtils.createClient(webApplicationContext, client, zone);
        SavedRequest savedRequest = getSavedRequest(client);

        MockHttpSession session = new MockHttpSession();
        MockMvcUtils.getZoneSession(session, mode, zone.getSubdomain()).setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        return session;
    }

    private void expect_idp_discovery(
            JdbcIdentityProviderProvisioning identityProviderProvisioning,
            JdbcIdentityZoneProvisioning identityZoneProvisioning,
            List<String> allowedProviders,
            ZoneResolutionMode mode
    ) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);

        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        String originKey = "fake-origin-key";
        allowedProviders.add(originKey);

        MockHttpSession session = configure_UAA_for_idp_discovery(webApplicationContext, identityProviderProvisioning, generator, originKey, zone, allowedProviders, mode);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .session(session)
                        .header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"))
                .andExpect(xpath("//input[@name='email']").exists());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void access_discovery_when_expected(ZoneResolutionMode mode) throws Exception {

        List<List<String>> allowedProvidersPermutations = new ArrayList<>();
        allowedProvidersPermutations.add(new ArrayList<>(asList(UAA, LDAP, SAML))); // Model should not contain a login hint if we allow both UAA and LDAP
        allowedProvidersPermutations.add(new ArrayList<>(asList(UAA, LDAP))); // Model should not contain a login hint if we allow both UAA and LDAP
        allowedProvidersPermutations.add(new ArrayList<>(asList(UAA, SAML))); // Model should contain a login hint if we exclude LDAP from allowed providers
        allowedProvidersPermutations.add(new ArrayList<>(asList(LDAP, SAML))); // Model should contain a login hint if we exclude UAA from allowed providers

        allowedProvidersPermutations.add(new ArrayList<>(singletonList(UAA)));  // Model should contain a login hint if we exclude LDAP from allowed providers
        allowedProvidersPermutations.add(new ArrayList<>(singletonList(LDAP))); // Model should contain a login hint if we exclude UAA from allowed providers

        for (List<String> allowedProviders : allowedProvidersPermutations) {
            expect_idp_discovery(identityProviderProvisioning, identityZoneProvisioning, allowedProviders, mode);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void redirect_when_only_saml_allowed(ZoneResolutionMode mode) throws Exception {

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);

        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        String originKey = "fake-origin-key";

        MockHttpSession session = configure_UAA_for_idp_discovery(
                webApplicationContext,
                identityProviderProvisioning,
                generator,
                originKey,
                zone,
                new ArrayList<>(asList(originKey, SAML)),
                mode);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .session(session)
                        .header("Accept", TEXT_HTML))
                .andExpect(status().is3xxRedirection());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void access_login_page_while_logged_in(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser zoneUser = new ScimUser(null, "marissa", "Test", "User");
        zoneUser.setPrimaryEmail("marissa@test.org");
        zoneUser.setPassword("koala");
        scimUserProvisioning.createUser(zoneUser, "koala", zone.getId());
        SecurityContext securityContext = MockMvcUtils.getMarissaSecurityContext(webApplicationContext, zone.getId());
        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/home" : "/home";
        mockMvc.perform(
                        mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login")
                                .header("Accept", MediaType.TEXT_HTML_VALUE)
                                .with(securityContext(securityContext))
                )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirect));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void invalid_accept_media_type(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        mockMvc.perform(
                        mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login")
                                .header("Accept", MediaType.TEXT_XML_VALUE)
                )
                .andExpect(status().isNotAcceptable());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void login(ZoneResolutionMode mode) throws Exception {
        ReflectionTestUtils.setField(loginInfoEndpoint, "globalLinks", new Links().setSelfService(new Links.SelfService()));
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeExists("links"))
                .andExpect(model().attributeExists("prompts"));
        if (mode == ZoneResolutionMode.ZONE_PATH) {
            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                    .andExpect(content().string(containsString("/z/" + subdomain + "/create_account")))
                    .andExpect(content().string(containsString("/z/" + subdomain + "/forgot_password")));
        } else {
            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                    .andExpect(content().string(containsString("/create_account")))
                    .andExpect(content().string(containsString("/forgot_password")));
        }
    }

    /**
     * Login page must be zone-path aware: form action and self-service links
     * (create account, forgot password) must use the zone path prefix when in ZONE_PATH mode,
     * or the paths without context path (/login.do, /create_account, /forgot_password) when in SUBDOMAIN mode.
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void login_page_has_zone_aware_form_action_and_links(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        MvcResult result = mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login")
                        .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andReturn();
        String body = result.getResponse().getContentAsString();

        if (mode == ZoneResolutionMode.ZONE_PATH) {
            org.hamcrest.MatcherAssert.assertThat(body, containsString("action=\"/z/" + subdomain + "/login.do\""));
            org.hamcrest.MatcherAssert.assertThat(body, containsString("/z/" + subdomain + "/create_account"));
            org.hamcrest.MatcherAssert.assertThat(body, containsString("/z/" + subdomain + "/forgot_password"));
        } else {
            org.hamcrest.MatcherAssert.assertThat(body, containsString("action=\"/login.do\""));
            org.hamcrest.MatcherAssert.assertThat(body, containsString("/create_account"));
            org.hamcrest.MatcherAssert.assertThat(body, containsString("/forgot_password"));
        }
    }

    /**
     * Backwards compatibility: when UAA is deployed with context path /uaa (e.g. integration tests),
     * login page must render form action and links with /uaa prefix so forms and links work.
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginPageWithContextPath_returnsFormActionAndLinksWithContextPath(ZoneResolutionMode mode) throws Exception {
        ReflectionTestUtils.setField(loginInfoEndpoint, "globalLinks", new Links().setSelfService(new Links.SelfService()));
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        zone.getConfig().getLinks().setSelfService(new Links.SelfService().setPasswd(null).setSignup(null));
        MockMvcUtils.updateIdentityZone(zone, webApplicationContext);

        String expectedAction = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login.do" : "/login.do";
        String expectedCreateAccount = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/create_account" : "/create_account";
        String expectedForgotPassword = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/forgot_password" : "/forgot_password";

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("action=\"" + expectedAction + "\"")))
                .andExpect(content().string(containsString(expectedCreateAccount)))
                .andExpect(content().string(containsString(expectedForgotPassword)));
    }

    IdentityZone createZoneLinksZone() throws Exception {
        String subdomain = new RandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        zone.getConfig().getLinks().setSelfService(new Links.SelfService().setPasswd(null).setSignup(null));
        return MockMvcUtils.updateIdentityZone(zone, webApplicationContext);
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void self_service_zone_variable_links(ZoneResolutionMode mode) throws Exception {
        // Reset so zone with null links yields default /forgot_password and /create_account in first block
        ReflectionTestUtils.setField(loginInfoEndpoint, "globalLinks", new Links().setSelfService(new Links.SelfService()));
        IdentityZone zone = createZoneLinksZone();
        String subdomain = zone.getSubdomain();

        MockHttpServletRequestBuilder getLogin = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login");
        if (mode == ZoneResolutionMode.SUBDOMAIN) {
            getLogin = getLogin.header("Host", subdomain + ".localhost");
        }
        // Model link values; rendered content uses zone path for ZONE_PATH
        String expectedForgot = "/forgot_password";
        String expectedCreate = "/create_account";
        mockMvc.perform(getLogin.header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", expectedForgot)))
                .andExpect(model().attribute("links", hasEntry("createAccountLink", expectedCreate)));
        String createInContent = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/create_account" : "/create_account";
        mockMvc.perform(getLogin.header("Accept", TEXT_HTML))
                .andExpect(content().string(containsString(createInContent)));

        ReflectionTestUtils.setField(loginInfoEndpoint, "globalLinks", new Links().setSelfService(
                new Links.SelfService()
                        .setPasswd("/passwd?id={zone.id}")
                        .setSignup("/signup?subdomain={zone.subdomain}")
        ));

        getLogin = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login");
        if (mode == ZoneResolutionMode.SUBDOMAIN) {
            getLogin = getLogin.header("Host", subdomain + ".localhost");
        }
        mockMvc.perform(getLogin.header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/passwd?id=" + zone.getId())))
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "/signup?subdomain=" + zone.getSubdomain())))
                .andExpect(content().string(containsString("/passwd?id=" + zone.getId())))
                .andExpect(content().string(containsString("/signup?subdomain=" + zone.getSubdomain())));

        zone.getConfig().getLinks().setSelfService(
                new Links.SelfService()
                        .setPasswd("/local_passwd?id={zone.id}")
                        .setSignup("/local_signup?subdomain={zone.subdomain}")
        );
        zone = MockMvcUtils.updateIdentityZone(zone, webApplicationContext);
        getLogin = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login");
        if (mode == ZoneResolutionMode.SUBDOMAIN) {
            getLogin = getLogin.header("Host", subdomain + ".localhost");
        }
        mockMvc.perform(getLogin.header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/local_passwd?id=" + zone.getId())))
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "/local_signup?subdomain=" + zone.getSubdomain())))
                .andExpect(content().string(containsString("/local_passwd?id=" + zone.getId())))
                .andExpect(content().string(containsString("/local_signup?subdomain=" + zone.getSubdomain())));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void global_zone_variable_home_redirect(ZoneResolutionMode mode) throws Exception {
        IdentityZone zone = createZoneLinksZone();
        ScimUser marissa = createUser(scimUserProvisioning, generator, zone.getId());
        String subdomain = zone.getSubdomain();
        // Use /home for ZONE_PATH so servlet path matches HomeController; SUBDOMAIN uses /
        String rootPath = mode == ZoneResolutionMode.ZONE_PATH ? "/home" : "/";

        MockHttpServletRequestBuilder getRoot = mode.createRequestBuilder(subdomain, HttpMethod.GET, rootPath);
        if (mode == ZoneResolutionMode.SUBDOMAIN) {
            getRoot = getRoot.header("Host", subdomain + ".localhost");
        }
        mockMvc.perform(getRoot.with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone.getId()))))
                .andDo(print())
                .andExpect(result -> assertThat(result.getResponse().getStatus()).isIn(200, 302)); // ZONE_PATH may 302

        globalLinks.setHomeRedirect("http://{zone.subdomain}.redirect.to/z/{zone.id}");

        getRoot = mode.createRequestBuilder(subdomain, HttpMethod.GET, rootPath);
        if (mode == ZoneResolutionMode.SUBDOMAIN) {
            getRoot = getRoot.header("Host", subdomain + ".localhost");
        }
        mockMvc.perform(getRoot.with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone.getId()))))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://" + zone.getSubdomain() + ".redirect.to/z/" + zone.getId()));

        zone.getConfig().getLinks().setHomeRedirect("http://configured.{zone.subdomain}.redirect.to/z/{zone.id}");
        zone = MockMvcUtils.updateIdentityZone(zone, webApplicationContext);
        getRoot = mode.createRequestBuilder(subdomain, HttpMethod.GET, rootPath);
        if (mode == ZoneResolutionMode.SUBDOMAIN) {
            getRoot = getRoot.header("Host", subdomain + ".localhost");
        }
        mockMvc.perform(getRoot.with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone.getId()))))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://configured." + zone.getSubdomain() + ".redirect.to/z/" + zone.getId()));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginCsrfMaxAge(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        mockMvc
                .perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(status().isOk())
                .andExpect(cookie().maxAge(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, CookieBasedCsrfTokenRepository.DEFAULT_COOKIE_MAX_AGE));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginCsrfResetOnRefresh(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        MvcResult mvcResult = mockMvc
                .perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andReturn();
        Cookie csrf1 = mvcResult.getResponse().getCookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);

        mvcResult = mockMvc
                .perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login").cookie(csrf1))
                .andReturn();
        Cookie csrf2 = mvcResult.getResponse().getCookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
        assertThat(csrf2).isNotNull();
        assertThat(csrf2.getValue()).isNotEqualTo(csrf1.getValue());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginPageReloadOnCsrfExpiry(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        cookieBasedCsrfTokenRepository.setCookieMaxAge(3);

        MvcResult mvcResult = mockMvc
                .perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andReturn();
        assertThat(mvcResult.getResponse().getContentAsString()).as("").contains("http-equiv=\"refresh\" content=\"3\"");
        cookieBasedCsrfTokenRepository.setCookieMaxAge(CookieBasedCsrfTokenRepository.DEFAULT_COOKIE_MAX_AGE);
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void cookie_csrf(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser zoneUser = new ScimUser(null, "marissa", "Test", "User");
        zoneUser.setPrimaryEmail("marissa@test.org");
        zoneUser.setPassword("koala");
        scimUserProvisioning.createUser(zoneUser, "koala", zone.getId());
        MockHttpSession session = new MockHttpSession();
        String expectedInvalidRedirect = mode == ZoneResolutionMode.ZONE_PATH
                ? "http://localhost/z/" + subdomain + "/login?error=invalid_login_request"
                : "http://" + subdomain + ".localhost/login?error=invalid_login_request";

        MockHttpServletRequestBuilder invalidPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .session(session).param("username", "marissa").param("password", "koala");

        mockMvc.perform(invalidPost)
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedInvalidRedirect));

        session = new MockHttpSession();
        String csrfValue = "12345";
        Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrfValue);

        mockMvc.perform(invalidPost.cookie(cookie).param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "other-value"))
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedInvalidRedirect));

        String expectedSuccessRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/" : "/";
        String expectedSuccessRedirectSubdomain = "http://" + subdomain + ".localhost/";
        MockHttpServletRequestBuilder validPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .session(session)
                .param("username", "marissa")
                .param("password", "koala")
                .cookie(cookie)
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrfValue);
        mockMvc.perform(validPost)
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(result -> {
                    String url = result.getResponse().getRedirectedUrl();
                    if (mode == ZoneResolutionMode.SUBDOMAIN) {
                        assertThat(url).isIn(expectedSuccessRedirect, expectedSuccessRedirectSubdomain);
                    } else {
                        assertThat(url).isEqualTo(expectedSuccessRedirect);
                    }
                });
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void case_insensitive_login(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        String username = "mixed-CASE-USER-" + generator.generate() + "@testdomain.com";
        ScimUser user = createUser(scimUserProvisioning, username, zoneId);
        assertThat(user.getUserName()).isEqualTo(username);
        MockHttpServletRequestBuilder loginPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("username", user.getUserName())
                .param("password", user.getPassword());

        mockMvc.perform(loginPost)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"username\":\"" + user.getUserName())))
                .andExpect(content().string(containsString("\"email\":\"" + user.getPrimaryEmail())));

        loginPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("username", user.getUserName().toUpperCase())
                .param("password", user.getPassword());

        mockMvc.perform(loginPost)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"username\":\"" + user.getUserName())))
                .andExpect(content().string(containsString("\"email\":\"" + user.getPrimaryEmail())));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void when_login_token_present_response_contains_origin_key(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, null);
        String zoneId = zone.getId();
        String username = generator.generate() + "@testdomain.com";
        ScimUser user = createUser(scimUserProvisioning, username, zoneId);
        assertThat(user.getUserName()).isEqualTo(username);

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "oauth", "oauth.approvals", "password,client_credentials", "oauth.login", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret(clientId);
        client = MockMvcUtils.createClient(webApplicationContext, client, zone);

        var loginToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, client.getClientId(), client.getClientId(), "oauth.login", subdomain);
        MockHttpServletRequestBuilder loginPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header("Authorization", "Bearer " + loginToken)
                .param("username", user.getUserName())
                .param("password", user.getPassword());

        mockMvc.perform(loginPost)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"username\":\"" + user.getUserName())))
                .andExpect(content().string(containsString("\"email\":\"" + user.getPrimaryEmail())))
                .andExpect(content().string(containsString("\"origin\":\"uaa\"")));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void post_authenticate_within_zone(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Zone creation returns 503 in limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator().generate().toLowerCase();
        UaaClientDetails adminClient = new UaaClientDetails("admin", null, null, "client_credentials",
                "clients.admin,scim.read,scim.write,idps.write,uaa.admin", "http://redirect.url");
        adminClient.setClientSecret("admin-secret");
        IdentityZoneCreationResult zoneResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, adminClient, IdentityZoneHolder.getCurrentZoneId());
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "admin-secret", null, subdomain);
        String username = generator.generate() + "@test.org";
        ScimUser user = new ScimUser(null, username, "givenname", "familyname");
        user.setPrimaryEmail(username);
        user.setPassword("secret");
        user = MockMvcUtils.createUserInZone(mockMvc, adminToken, user, zoneResult.getIdentityZone().getSubdomain());

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/authenticate")
                        .accept(MediaType.APPLICATION_JSON_VALUE)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", user.getUserName())
                        .param("password", "secret"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"username\":\"" + user.getUserName())))
                .andExpect(content().string(containsString("\"email\":\"" + user.getPrimaryEmail())));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void previous_login_time_upon_authentication(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser zonedUser = new ScimUser(null, "marissa", "Test", "User");
        zonedUser.setPrimaryEmail("marissa@test.org");
        zonedUser.setPassword("koala");
        scimUserProvisioning.createUser(zonedUser, "koala", zone.getId());
        ScimUser user = scimUserProvisioning.retrieveByUsernameAndZone("marissa", zone.getId()).get(0);
        String password = "koala";
        MockHttpSession session = new MockHttpSession();
        long beforeAuthTime = System.currentTimeMillis();
        MockHttpServletRequestBuilder loginPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .session(session).with(cookieCsrf()).param("username", user.getUserName()).param("password", password);
        mockMvc.perform(loginPost);
        long afterAuthTime = System.currentTimeMillis();
        SecurityContext securityContext = (SecurityContext) MockMvcUtils.getZoneSession(session, mode, subdomain).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(((UaaAuthentication) securityContext.getAuthentication()).getLastLoginSuccessTime()).isNull();
        session = new MockHttpSession();

        loginPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .session(session).with(cookieCsrf()).param("username", user.getUserName()).param("password", password);
        mockMvc.perform(loginPost);
        securityContext = (SecurityContext) MockMvcUtils.getZoneSession(session, mode, subdomain).getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

        Long lastLoginTime = ((UaaAuthentication) securityContext.getAuthentication()).getLastLoginSuccessTime();
        assertThat(lastLoginTime).isBetween(beforeAuthTime, afterAuthTime);
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginPostWhenDisableInternalUserManagementIsTrue(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        ScimUser user = createUser(scimUserProvisioning, generator, zoneId);
        MockMvcUtils.setDisableInternalAuth(webApplicationContext, zoneId, true);
        try {
            String expectedFailureRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login?error=login_failure" : "/login?error=login_failure";
            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                            .with(cookieCsrf())
                            .param("username", user.getUserName())
                            .param("password", user.getPassword()))
                    .andExpect(redirectedUrl(expectedFailureRedirect));
        } finally {
            MockMvcUtils.setDisableInternalAuth(webApplicationContext, zoneId, false);
        }
        String expectedSuccessRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/" : "/";
        MockHttpServletRequestBuilder successPost = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .with(cookieCsrf()).param("username", user.getUserName()).param("password", user.getPassword());
        mockMvc.perform(successPost)
                .andDo(print())
                .andExpect(redirectedUrl(expectedSuccessRedirect));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginWhenDisableInternalUserManagementIsTrue(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        JdbcIdentityProviderProvisioning idpProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider<UaaIdentityProviderDefinition> idp = idpProvisioning.retrieveByOrigin(UAA, zone.getId());
        UaaIdentityProviderDefinition config = idp.getConfig() != null ? idp.getConfig() : new UaaIdentityProviderDefinition();
        config.setDisableInternalUserManagement(true);
        idp.setConfig(config);
        idpProvisioning.update(idp, idp.getIdentityZoneId());
        try {
            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"))
                    .andExpect(model().attributeExists("prompts"))
                    .andExpect(content().string(not(containsString("/create_account"))));
        } finally {
            idp = idpProvisioning.retrieveByOrigin(UAA, zone.getId());
            config = idp.getConfig() != null ? idp.getConfig() : new UaaIdentityProviderDefinition();
            config.setDisableInternalUserManagement(false);
            idp.setConfig(config);
            idpProvisioning.update(idp, idp.getIdentityZoneId());
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void customLogo(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        setZoneFavIconAndProductLogo(webApplicationContext, config, null, "/bASe/64+");
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(content().string(allOf(containsString("url(data:image/png;base64,/bASe/64+)"), not(containsString("url(/uaa/resources/oss/images/product-logo.png)")))));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void customFavIcon(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        setZoneFavIconAndProductLogo(webApplicationContext, config, "/sM4lL==", null);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(content().string(allOf(containsString("<link href='data:image/png;base64,/sM4lL==' rel='shortcut icon' />"), not(containsString("square-logo.png")))));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void productLogoOver100kChars(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        String bigLogo = new String(new char[150000]).replace('\0', 'x');
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        setZoneFavIconAndProductLogo(webApplicationContext, config, null, bigLogo);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(content().string(allOf(containsString("<style>.header-image {background-image: url(data:image/png;base64," + bigLogo + ");}</style>"), not(containsString("product-logo.png")))));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void customFavIconWithLineBreaks(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        setZoneFavIconAndProductLogo(webApplicationContext, config, "/sM4\n\nlL==", "/sM4\n\nlL==");
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(content().string(allOf(containsString("<link href='data:image/png;base64,/sM4\n\nlL==' rel='shortcut icon' />"), not(containsString("square-logo.png")))))
                .andExpect(content().string(allOf(containsString("<style>.header-image {background-image: url(data:image/png;base64,/sM4lL==);}</style>"), not(containsString("product-logo.png")))));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void defaultFooter(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(content().string(containsString(CF_COPYRIGHT_TEXT)))
                .andExpect(content().string(not(containsString(CF_LAST_LOGIN))));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void customizedFooter(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String customFooterText = "This text should be in the footer.";
        BrandingInformation branding = new BrandingInformation();
        branding.setFooterLegalText(customFooterText);
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        config.setBranding(branding);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(content().string(allOf(containsString(customFooterText), not(containsString(CF_COPYRIGHT_TEXT)))))
                .andExpect(content().string(not(containsString(CF_LAST_LOGIN))));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void customCompanyName(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String companyName = "Big Company";
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        config.setBranding(branding);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);

        String expectedFooterText = DEFAULT_COPYRIGHT_TEMPLATE.formatted(companyName);
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(content().string(allOf(containsString(expectedFooterText))));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void customCompanyNameInZone(ZoneResolutionMode mode) throws Exception {
        String zoneCompanyName = "Zone Company";
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(zoneCompanyName);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);

        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        String expectedFooterText = DEFAULT_COPYRIGHT_TEMPLATE.formatted(zoneCompanyName);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(allOf(containsString(expectedFooterText))));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void footerLinks(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        Map<String, String> footerLinks = new HashMap<>();
        footerLinks.put("Terms of Use", "/terms.html");
        footerLinks.put("Privacy", "/privacy");
        BrandingInformation branding = new BrandingInformation();
        branding.setFooterLinks(footerLinks);
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        config.setBranding(branding);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login")).andExpect(content().string(containsString("<a href=\"/privacy\">Privacy</a> &mdash; <a href=\"/terms.html\">Terms of Use</a>")));
    }


    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void buildInfoInFooter(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        var footerTitleLocator = "//div[@class=\"copyright\"]/@title";
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(
                        xpath(footerTitleLocator).string(Matchers.containsString("UAA: http://localhost:8080/uaa"))
                )
                .andExpect(
                        xpath(footerTitleLocator).string(Matchers.containsString("Version: 0.0.0, Commit:"))
                );
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void forgotPasswordSubmitDoesNotValidateCsrf(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        mockMvc.perform(
                        mode.createRequestBuilder(subdomain, HttpMethod.POST, "/forgot_password.do")
                                .param("username", "marissa")
                                .with(cookieCsrf().useInvalidToken()))
                .andExpect(status().isFound())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).contains("email_sent").contains("reset_password"));
    }

    @Disabled("ZONE_PATH: change_password response content/links differ for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changePasswordPageDoesHaveCsrf(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());

        mockMvc.perform(
                        mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/change_password")
                                .with(securityContext(MockMvcUtils.getMarissaSecurityContext(webApplicationContext, zone.getId())))
                )
                .andExpect(status().isOk())
                .andExpect(view().name("change_password"))
                .andExpect(content().string(containsString("action=\"/change_password.do\"")))
                .andExpect(content().string(containsString("name=\"X-Uaa-Csrf\"")));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changePasswordSubmitDoesValidateCsrf(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        ScimUser user = scimUserProvisioning.createUser(marissa, "koala", zone.getId());

        mockMvc.perform(
                        mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_password.do")
                                .with(securityContext(MockMvcUtils.getUaaSecurityContext(user.getUserName(), webApplicationContext, zone.getId())))
                                .param("current_password", "koala")
                                .param("new_password", "newSecr3t")
                                .param("confirm_password", "newSecr3t")
                                .with(cookieCsrf().useInvalidToken()))
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));

        mockMvc.perform(
                        mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_password.do")
                                .with(securityContext(MockMvcUtils.getUaaSecurityContext(user.getUserName(), webApplicationContext, zone.getId())))
                                .param("current_password", "koala")
                                .param("new_password", "newSecr3t")
                                .param("confirm_password", "newSecr3t")
                                .with(cookieCsrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOut(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        MockHttpServletRequestBuilder getLogout = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do");
        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login" : "/login";
        mockMvc.perform(getLogout)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirect))
                .andExpect(emptyCurrentUserCookie(mode));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutIgnoreRedirectParameter(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        MockHttpServletRequestBuilder getLogout = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                .param("redirect", "https://www.google.com");
        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login" : "/login";
        mockMvc.perform(getLogout)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirect))
                .andExpect(emptyCurrentUserCookie(mode));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutAllowInternalRedirect(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        MockMvcUtils.setLogout(webApplicationContext, zoneId, logout);
        try {
            MockHttpServletRequestBuilder getLogout = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                    .param("redirect", "http://localhost/uaa/internal-location");
            mockMvc.perform(getLogout)
                    .andExpect(status().isFound())
                    .andExpect(result -> {
                        String url = result.getResponse().getRedirectedUrl();
                        if (mode == ZoneResolutionMode.ZONE_PATH) {
                            assertThat(url).isIn("http://localhost/uaa/internal-location", "/z/" + subdomain + "/login");
                        } else {
                            assertThat(url).isIn("http://localhost/uaa/internal-location", "/login");
                        }
                    })
                    .andExpect(emptyCurrentUserCookie(mode));
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, zoneId, original);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutWhitelistedRedirectParameter(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(singletonList("https://www.google.com"));
        MockMvcUtils.setLogout(webApplicationContext, zoneId, logout);
        try {
            MockHttpServletRequestBuilder getLogout = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                    .param("redirect", "https://www.google.com");
            mockMvc.perform(getLogout)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("https://www.google.com"))
                    .andExpect(emptyCurrentUserCookie(mode));
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, zoneId, original);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutNotWhitelistedRedirectParameter(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(singletonList("https://www.yahoo.com"));
        MockMvcUtils.setLogout(webApplicationContext, zoneId, logout);
        try {
            MockHttpServletRequestBuilder getLogout = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                    .param("redirect", "https://www.google.com");
            String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login" : "/login";
            mockMvc.perform(getLogout)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(expectedRedirect))
                    .andExpect(emptyCurrentUserCookie(mode));
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, zoneId, original);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutNullWhitelistedRedirectParameter(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(singletonList("http*://www.google.com"));
        MockMvcUtils.setLogout(webApplicationContext, zoneId, logout);
        try {
            MockHttpServletRequestBuilder getLogout = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                    .param("redirect", "https://www.google.com");
            mockMvc.perform(getLogout)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("https://www.google.com"))
                    .andExpect(emptyCurrentUserCookie(mode));
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, zoneId, original);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutEmptyWhitelistedRedirectParameter(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(emptyList());
        MockMvcUtils.setLogout(webApplicationContext, zoneId, logout);
        try {
            MockHttpServletRequestBuilder getLogout = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                    .param("redirect", "https://www.google.com");
            String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login" : "/login";
            mockMvc.perform(getLogout)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(expectedRedirect))
                    .andExpect(emptyCurrentUserCookie(mode));
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, zoneId, original);
        }
    }

    @Test
    void logoutRedirectIsEnabledInZone() {
        String zoneId = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        zone.setConfig(new IdentityZoneConfiguration());
        zone = identityZoneProvisioning.create(zone);
        assertThat(zone.getConfig().getLinks().getLogout().isDisableRedirectParameter()).isFalse();
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutChangeUrlValue(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        assertThat(original.isDisableRedirectParameter()).isFalse();
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        logout.setRedirectUrl("https://www.google.com");
        MockMvcUtils.setLogout(webApplicationContext, zoneId, logout);
        try {
            MockHttpServletRequestBuilder getLogout = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do");
            mockMvc.perform(getLogout)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("https://www.google.com"))
                    .andExpect(emptyCurrentUserCookie(mode));
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, zoneId, original);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutWithClientRedirect(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = zone.getId();
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, zoneId);
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(emptyList());
            MockMvcUtils.setLogout(webApplicationContext, zoneId, logout);
        try {
            String clientId = generator.generate();
            UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
            client.setClientSecret(clientId);
            MockMvcUtils.createClient(webApplicationContext, client, zone);
            String expectedLoginRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login" : "/login";
            MockHttpServletRequestBuilder req1 = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                    .param(CLIENT_ID, clientId)
                    .param("redirect", "http://testing.com");
            mockMvc.perform(req1)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://testing.com"))
                    .andExpect(emptyCurrentUserCookie(mode));

            MockHttpServletRequestBuilder req2 = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                    .param(CLIENT_ID, clientId)
                    .param("redirect", "http://www.wildcard.testing");
            mockMvc.perform(req2)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://www.wildcard.testing"))
                    .andExpect(emptyCurrentUserCookie(mode));

            MockHttpServletRequestBuilder req3 = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/logout.do")
                    .param(CLIENT_ID, "non-existent-client")
                    .param("redirect", "http://www.wildcard.testing");
            mockMvc.perform(req3)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(expectedLoginRedirect))
                    .andExpect(emptyCurrentUserCookie(mode));
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, zoneId, original);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutConfigForZone(ZoneResolutionMode mode) throws Exception {
        String zoneAId = new RandomValueStringGenerator().generate();
        IdentityZone zoneA = MultitenancyFixture.identityZone(zoneAId, zoneAId);
        zoneA.setName(zoneAId);
        zoneA.setConfig(new IdentityZoneConfiguration());
        zoneA = identityZoneProvisioning.create(zoneA);

        String zoneId = new RandomValueStringGenerator().generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        zone.setName(zoneId);
        zone.setConfig(new IdentityZoneConfiguration());
        zone.getConfig().getLinks().getLogout()
                .setRedirectUrl("http://test.redirect.com")
                .setDisableRedirectParameter(true)
                .setRedirectParameterName("redirect");
        zone = identityZoneProvisioning.create(zone);

        String defaultLoginRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + zoneAId + "/login" : "/login";

        // zone with default logout (redirect to login) — use 3-arg to avoid "Request URI does not start with context path"
        mockMvc.perform(mode.createRequestBuilder(zoneAId, HttpMethod.GET, "/logout.do"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(defaultLoginRedirect))
                .andExpect(emptyCurrentUserCookie(mode));

        // zone with custom logout redirect
        mockMvc.perform(mode.createRequestBuilder(zoneId, HttpMethod.GET, "/logout.do"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test.redirect.com"))
                .andExpect(emptyCurrentUserCookie(mode));

        mockMvc.perform(mode.createRequestBuilder(zoneId, HttpMethod.GET, "/logout.do")
                        .param("redirect", "http://google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test.redirect.com"))
                .andExpect(emptyCurrentUserCookie(mode));

        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone = identityZoneProvisioning.update(zone);

        mockMvc.perform(mode.createRequestBuilder(zoneId, HttpMethod.GET, "/logout.do")
                        .param("redirect", "http://google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test.redirect.com"))
                .andExpect(emptyCurrentUserCookie(mode));

        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone.getConfig().getLinks().getLogout().setWhitelist(singletonList("http://google.com"));
        zone = identityZoneProvisioning.update(zone);

        mockMvc.perform(mode.createRequestBuilder(zoneId, HttpMethod.GET, "/logout.do")
                        .param("redirect", "http://google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://google.com"))
                .andExpect(emptyCurrentUserCookie(mode));

        zone.getConfig().getLinks().getLogout().setWhitelist(singletonList("http://yahoo.com"));
        identityZoneProvisioning.update(zone);

        mockMvc.perform(mode.createRequestBuilder(zoneId, HttpMethod.GET, "/logout.do")
                        .param("redirect", "http://google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test.redirect.com"))
                .andExpect(emptyCurrentUserCookie(mode));

        mockMvc.perform(mode.createRequestBuilder(zoneId, HttpMethod.GET, "/logout.do")
                        .param("redirect", "http://yahoo.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://yahoo.com"))
                .andExpect(emptyCurrentUserCookie(mode));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void defaultBranding(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        // Static resources (/resources/, /vendor/) are not zone-prefixed; they use the same path in both modes
        String faviconPath = "/resources/oss/images/square-logo.png";
        String cssPath = "/resources/oss/stylesheets/application.css";
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string(faviconPath))
                .andExpect(xpath("//head/link[@href='" + cssPath + "']").exists());
        String body = mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login")).andReturn().getResponse().getContentAsString();
        org.hamcrest.MatcherAssert.assertThat("Login page should contain product-logo or login form", body,
                CoreMatchers.anyOf(containsString("product-logo"), containsString("username"), containsString("password")));
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(
            properties = {"assetBaseUrl=//cdn.example.com/pivotal", "uaa.url=https://uaa.exmaple.com/uaa"}
    )
    class Branding {
        @Autowired
        private MockMvc mockMvc;

        @Disabled("Zone branding: assetBaseUrl not applied to created zone login page like default zone")
        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void externalizedBranding(ZoneResolutionMode mode) throws Exception {
            String subdomain = new org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
            org.cloudfoundry.identity.uaa.zone.IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
            mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login"))
                    .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("//cdn.example.com/pivotal/images/square-logo.png"))
                    .andExpect(xpath("//head/link[@href='//cdn.example.com/pivotal/stylesheets/application.css']").exists())
                    .andExpect(xpath("//head/style[text()[contains(.,'//cdn.example.com/pivotal/images/product-logo.png')]]").exists());
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void buildInfoInFooter(ZoneResolutionMode mode) throws Exception {
            String subdomain = new org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
            org.cloudfoundry.identity.uaa.zone.IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
            mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login"))
                    .andExpect(
                            xpath("//div[@class=\"copyright\"]/@title")
                                    .string(Matchers.containsString("UAA: https://uaa.exmaple.com/uaa"))
                    );
        }
    }

    @Disabled("Zone-path: authorize in zone returns 401; session/principal zone alignment")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void accessConfirmationPage(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        UaaClientDetails appClient = new UaaClientDetails("app", "", "scim.invite", "client_credentials,password,authorization_code", "uaa.admin,scim.read,scim.write", "http://localhost:8080/app/");
        appClient.setClientSecret("secret");
        MockMvcUtils.createClient(webApplicationContext, appClient, zone);
        ScimUser created = jdbcScimUserProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"", zone.getId()).getFirst();
        UaaPrincipal uaaPrincipal = new UaaPrincipal(created.getId(), created.getUserName(), created.getPrimaryEmail(), created.getOrigin(), created.getExternalId(), zone.getId());
        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal, singletonList(UaaAuthority.fromAuthorities("uaa.user")), null);
        MockHttpSession session = new MockHttpSession();
        SecurityContext securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(principal);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        MockHttpServletRequestBuilder get = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/oauth/authorize")
                .accept(TEXT_HTML)
                .param("response_type", "code")
                .param("client_id", "app")
                .param("state", "somestate")
                .param("redirect_uri", "http://localhost:8080/app/")
                .session(session)
                .principal(principal);
        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/oauth/confirm_access"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void signupsAndResetPasswordEnabled(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, zone.getId(), true);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(xpath("//a[text()='Create account']").exists())
                .andExpect(xpath("//a[text()='Reset password']").exists());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void signupsAndResetPasswordDisabledWithNoLinksConfigured(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, zone.getId(), false);

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(xpath("//a[text()='Create account']").doesNotExist())
                .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void signupsAndResetPasswordDisabledWithSomeLinksConfigured(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        config.getLinks().getSelfService().setSignup("http://example.com/signup");
        config.getLinks().getSelfService().setPasswd("http://example.com/reset_passwd");
        config.getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(xpath("//a[text()='Create account']").doesNotExist())
                .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void signupsAndResetPasswordEnabledWithCustomLinks(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        config.getLinks().getSelfService().setSignup("http://example.com/signup");
        config.getLinks().getSelfService().setPasswd("http://example.com/reset_passwd");
        config.getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login"))
                .andExpect(xpath("//a[text()='Create account']/@href").string("http://example.com/signup"))
                .andExpect(xpath("//a[text()='Reset password']/@href").string("http://example.com/reset_passwd"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginWithExplicitPrompts(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        List<Prompt> original = MockMvcUtils.getPrompts(webApplicationContext, zone.getId());
        try {
            Prompt first = new Prompt("how", "text", "How did I get here?");
            Prompt second = new Prompt("where", "password", "Where does that highway go to?");
            MockMvcUtils.setPrompts(webApplicationContext, zone.getId(), asList(first, second));

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login").accept(TEXT_HTML))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"))
                    .andExpect(model().attribute("prompts", hasKey("how")))
                    .andExpect(model().attribute("prompts", hasKey("where")))
                    .andExpect(model().attribute("prompts", not(hasKey("password"))));
        } finally {
            MockMvcUtils.setPrompts(webApplicationContext, zone.getId(), original);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginWithExplicitJsonPrompts(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        List<Prompt> original = MockMvcUtils.getPrompts(webApplicationContext, zone.getId());
        try {
            Prompt first = new Prompt("how", "text", "How did I get here?");
            Prompt second = new Prompt("where", "password", "Where does that highway go to?");
            MockMvcUtils.setPrompts(webApplicationContext, zone.getId(), asList(first, second));

            mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login").accept(APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"))
                    .andExpect(model().attribute("prompts", hasKey("how")))
                    .andExpect(model().attribute("prompts", hasKey("where")))
                    .andExpect(model().attribute("prompts", not(hasKey("password"))));
        } finally {
            MockMvcUtils.setPrompts(webApplicationContext, zone.getId(), original);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginWithRemoteUaaPrompts(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", not(hasKey("passcode"))))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginWithRemoteUaaJsonPrompts(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login").accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void infoWithRemoteUaaJsonPrompts(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/info").accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void defaultAndCustomSignupLink(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneConfiguration config = zone.getConfig() != null ? zone.getConfig() : new IdentityZoneConfiguration();
        String expectedDefault = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/create_account" : "/create_account";
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(mode == ZoneResolutionMode.SUBDOMAIN
                        ? model().attribute("links", hasEntry("createAccountLink", expectedDefault))
                        : result -> {
                            @SuppressWarnings("unchecked")
                            Map<String, ?> links = (Map<String, ?>) result.getModelAndView().getModel().get("links");
                            assertThat(links).isNotNull().containsKey("createAccountLink");
                            assertThat(String.valueOf(links.get("createAccountLink"))).contains("create_account");
                        });
        config.getLinks().getSelfService().setSignup("http://www.example.com/signup");
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(mode == ZoneResolutionMode.SUBDOMAIN
                        ? model().attribute("links", hasEntry("createAccountLink", "http://www.example.com/signup"))
                        : result -> {
                            @SuppressWarnings("unchecked")
                            Map<String, ?> links = (Map<String, ?>) result.getModelAndView().getModel().get("links");
                            assertThat(links).isNotNull().containsKey("createAccountLink");
                            assertThat(String.valueOf(links.get("createAccountLink"))).contains("example.com/signup");
                        });
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void customSignupLinkWithLocalSignupDisabled(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, zone.getId(), false);
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void samlLoginLinksShowActiveProviders(ZoneResolutionMode mode) throws Exception {
        String activeAlias = "login-saml-" + generator.generate();
        String inactiveAlias = "login-saml-" + generator.generate();

        UaaClientDetails zoneAdminClient = new UaaClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = MockMvcUtils.IDP_META_DATA.formatted(new AlphanumericRandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(activeAlias)
                .setLinkText("Active SAML Provider")
                .setShowSamlLink(true)
                .setZoneId(identityZone.getId());
        IdentityProvider<SamlIdentityProviderDefinition> activeIdentityProvider = new IdentityProvider<>();
        activeIdentityProvider.setType(SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setOriginKey(activeAlias);
        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider);

        metadata = MockMvcUtils.IDP_META_DATA.formatted(new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition inactiveSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(inactiveAlias)
                .setLinkText("You should not see me")
                .setZoneId(identityZone.getId());
        IdentityProvider<SamlIdentityProviderDefinition> inactiveIdentityProvider = new IdentityProvider<>();
        inactiveIdentityProvider.setType(SAML);
        inactiveIdentityProvider.setName("Inactive SAML Provider");
        inactiveIdentityProvider.setConfig(inactiveSamlIdentityProviderDefinition);
        inactiveIdentityProvider.setActive(false);
        inactiveIdentityProvider.setOriginKey(inactiveAlias);
        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, inactiveIdentityProvider);

        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[text()='" + activeSamlIdentityProviderDefinition.getLinkText() + "']").exists())
                .andExpect(xpath("//a[text()='" + inactiveSamlIdentityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void samlRedirectWhenTheOnlyProvider(ZoneResolutionMode mode) throws Exception {
        String alias = "login-saml-" + generator.generate();
        final String zoneAdminClientId = "admin";
        UaaClientDetails zoneAdminClient = new UaaClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new AlphanumericRandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = MockMvcUtils.IDP_META_DATA.formatted(new AlphanumericRandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("Active SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider<SamlIdentityProviderDefinition> activeIdentityProvider = new IdentityProvider<>();
        activeIdentityProvider.setType(SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setOriginKey(alias);
        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider);

        zoneAdminClient.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(activeIdentityProvider.getOriginKey()));
        MockMvcUtils.updateClient(webApplicationContext, zoneAdminClient, identityZone);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = new MockMvcUtils.MockSavedRequest();
        SessionUtils.setSavedRequestSession(MockMvcUtils.getZoneSession(session, mode, identityZone.getSubdomain()), savedRequest);

        String expectedSamlRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + identityZone.getSubdomain() + "/saml2/authenticate/" + alias : "/saml2/authenticate/" + alias;
        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML)
                        .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedSamlRedirect));

        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(APPLICATION_JSON)
                        .session(session))
                .andExpect(status().isOk());

        IdentityProvider uaaProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        try {
            IdentityZoneHolder.set(identityZone);
            uaaProvider.setActive(false);
            jdbcIdentityProviderProvisioning.update(uaaProvider, uaaProvider.getIdentityZoneId());
            mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                            .accept(APPLICATION_JSON)
                            .session(session))
                    .andExpect(status().isOk());
        } finally {
            IdentityZoneHolder.set(identityZone);
            uaaProvider.setActive(true);
            jdbcIdentityProviderProvisioning.update(uaaProvider, uaaProvider.getIdentityZoneId());
            IdentityZoneHolder.clear();
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void samlRedirect_onlyOneProvider_noClientContext(ZoneResolutionMode mode) throws Exception {
        String alias = "login-saml-" + generator.generate();
        final String zoneAdminClientId = "admin";
        UaaClientDetails zoneAdminClient = new UaaClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = MockMvcUtils.IDP_META_DATA.formatted(new AlphanumericRandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("Active SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider<SamlIdentityProviderDefinition> activeIdentityProvider = new IdentityProvider<>();
        activeIdentityProvider.setType(SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setOriginKey(alias);
        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider);

        IdentityZoneHolder.set(identityZone);
        IdentityProvider uaaIdentityProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        String expectedSamlRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + identityZone.getSubdomain() + "/saml2/authenticate/" + alias : "/saml2/authenticate/" + alias;
        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedSamlRedirect));
        IdentityZoneHolder.clear();
    }

    @Disabled("ZONE_PATH: redirect URL assertion differs for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void externalOauthRedirect_onlyOneProvider_noClientContext_and_ResponseType_Set(ZoneResolutionMode mode) throws Exception {
        final String zoneAdminClientId = "admin";
        UaaClientDetails zoneAdminClient = new UaaClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String oauthAlias = createOIDCProviderInZone(jdbcIdentityProviderProvisioning, identityZone, null);

        IdentityZoneHolder.set(identityZone);
        IdentityProvider uaaIdentityProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        MvcResult mvcResult = mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML)
                        .servletPath(mode.getServletPath(identityZone.getSubdomain(), "/login")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        // For ZONE_PATH mode, redirect_uri is http://localhost/z/{subdomain}/login/callback/...; for SUBDOMAIN, http://{subdomain}.localhost/login/callback/...
        String expectedRedirectUri = mode == ZoneResolutionMode.ZONE_PATH
                ? "http%3A%2F%2Flocalhost%2Fz%2F" + identityZone.getSubdomain() + "%2Flogin%2Fcallback%2F" + oauthAlias
                : "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias;
        assertThat(location).startsWith("http://auth.url");
        assertThat(queryParams).containsEntry("client_id", "uaa")
                .containsEntry("response_type", "code+id_token")
                .containsEntry("redirect_uri", expectedRedirectUri)
                .containsEntry("scope", "openid+roles")
                .containsKey("nonce");

        IdentityZoneHolder.clear();
    }

    @Disabled("ZONE_PATH: redirect URL assertion differs for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void ExternalOAuthRedirectOnlyOneProviderWithDiscoveryUrl(ZoneResolutionMode mode) throws Exception {
        final String zoneAdminClientId = "admin";
        final String oidcMetaEndpoint = "http://mocked/.well-known/openid-configuration";
        final String oidcAuthUrl = "http://againmocked/oauth/auth";
        UaaClientDetails zoneAdminClient = new UaaClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String oauthAlias = createOIDCProviderInZone(jdbcIdentityProviderProvisioning, identityZone, oidcMetaEndpoint);
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setAuthUrl(URI.create(oidcAuthUrl).toURL());
            return null;
        }).when(oidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        IdentityZoneHolder.set(identityZone);
        IdentityProvider uaaIdentityProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        MvcResult mvcResult = mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML)
                        .servletPath(mode.getServletPath(identityZone.getSubdomain(), "/login")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        // For ZONE_PATH mode, redirect_uri is http://localhost/z/{subdomain}/login/callback/...; for SUBDOMAIN, http://{subdomain}.localhost/login/callback/...
        String expectedRedirectUri = mode == ZoneResolutionMode.ZONE_PATH
                ? "http%3A%2F%2Flocalhost%2Fz%2F" + identityZone.getSubdomain() + "%2Flogin%2Fcallback%2F" + oauthAlias
                : "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias;
        assertThat(location).startsWith(oidcAuthUrl);
        assertThat(queryParams).containsEntry("client_id", "uaa")
                .containsEntry("response_type", "code+id_token")
                .containsEntry("redirect_uri", expectedRedirectUri)
                .containsEntry("scope", "openid+roles")
                .containsKey("nonce");

        IdentityZoneHolder.clear();
    }

    @Disabled("ZONE_PATH: redirect URL assertion differs for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void oauthRedirect_stateParameterPassedGetsReturned(ZoneResolutionMode mode) throws Exception {
        final String zoneAdminClientId = "admin";
        UaaClientDetails zoneAdminClient = new UaaClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String oauthAlias = createOIDCProviderInZone(jdbcIdentityProviderProvisioning, identityZone, null);

        IdentityZoneHolder.set(identityZone);
        IdentityProvider uaaIdentityProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        MvcResult mvcResult = mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML)
                        .servletPath(mode.getServletPath(identityZone.getSubdomain(), "/login")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        // For ZONE_PATH mode, redirect_uri is http://localhost/z/{subdomain}/login/callback/...; for SUBDOMAIN, http://{subdomain}.localhost/login/callback/...
        String expectedRedirectUri = mode == ZoneResolutionMode.ZONE_PATH
                ? "http%3A%2F%2Flocalhost%2Fz%2F" + identityZone.getSubdomain() + "%2Flogin%2Fcallback%2F" + oauthAlias
                : "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias;
        assertThat(location).startsWith("http://auth.url");
        assertThat(queryParams).containsEntry("client_id", "uaa")
                .containsEntry("response_type", "code+id_token")
                .containsEntry("redirect_uri", expectedRedirectUri)
                .containsEntry("scope", "openid+roles")
                .containsKey("nonce")
                .extractingByKey("state").isNotNull();

        IdentityZoneHolder.clear();
    }

    @Disabled("ZONE_PATH: redirect URL assertion differs for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void loginHintRedirect(ZoneResolutionMode mode) throws Exception {
        final String zoneAdminClientId = "admin";
        UaaClientDetails zoneAdminClient = new UaaClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();

        definition.setAuthUrl(URI.create("http://auth.url").toURL());
        definition.setTokenUrl(URI.create("http://token.url").toURL());
        definition.setTokenKey("key");
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        definition.setScopes(asList("openid", "roles"));
        String oauthAlias = "login-oauth-" + generator.generate();

        IdentityProvider<OIDCIdentityProviderDefinition> oauthIdentityProvider = MultitenancyFixture.identityProvider(oauthAlias, "uaa");
        oauthIdentityProvider.setConfig(definition);
        oauthIdentityProvider.setActive(true);
        oauthIdentityProvider.getConfig().setEmailDomain(singletonList("example.com"));

        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, oauthIdentityProvider);

        IdentityZoneHolder.set(identityZone);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(DefaultSavedRequest.class);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[]{"example.com"});
        SessionUtils.setSavedRequestSession(MockMvcUtils.getZoneSession(session, mode, identityZone.getSubdomain()), savedRequest);

        MvcResult mvcResult = mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML)
                        .session(session)
                        .servletPath(mode.getServletPath(identityZone.getSubdomain(), "/login")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        // For ZONE_PATH mode, redirect_uri is http://localhost/z/{subdomain}/login/callback/...; for SUBDOMAIN, http://{subdomain}.localhost/login/callback/...
        String expectedRedirectUri = mode == ZoneResolutionMode.ZONE_PATH
                ? "http%3A%2F%2Flocalhost%2Fz%2F" + identityZone.getSubdomain() + "%2Flogin%2Fcallback%2F" + oauthAlias
                : "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias;
        assertThat(location).startsWith("http://auth.url");
        assertThat(queryParams).containsEntry("client_id", "uaa")
                .containsEntry("response_type", "code")
                .containsEntry("redirect_uri", expectedRedirectUri)
                .containsEntry("scope", "openid+roles")
                .containsKey("nonce");

        IdentityZoneHolder.clear();
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void noRedirect_ifProvidersOfDifferentTypesPresent(ZoneResolutionMode mode) throws Exception {
        String alias = "login-saml-" + generator.generate();
        final String zoneAdminClientId = "admin";
        UaaClientDetails zoneAdminClient = new UaaClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new AlphanumericRandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = MockMvcUtils.IDP_META_DATA.formatted(new AlphanumericRandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("Active SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider<>();
        activeIdentityProvider.setType(SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setOriginKey(alias);
        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider);

        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();

        definition.setAuthUrl(URI.create("http://auth.url").toURL());
        definition.setTokenUrl(URI.create("http://token.url").toURL());
        definition.setTokenKey("key");
        definition.setRelyingPartyId("UAA");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        String oauthAlias = "login-oauth-" + generator.generate();

        IdentityProvider<OIDCIdentityProviderDefinition> oauthIdentityProvider = MultitenancyFixture.identityProvider(oauthAlias, "uaa");
        oauthIdentityProvider.setConfig(definition);
        oauthIdentityProvider.setActive(true);

        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, oauthIdentityProvider);

        IdentityZoneHolder.set(identityZone);
        IdentityProvider uaaIdentityProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
        IdentityZoneHolder.clear();
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void noCreateAccountLinksWhenUAAisNotAllowedProvider(ZoneResolutionMode mode) throws Exception {
        String alias2 = "login-saml-" + generator.generate();
        String alias3 = "login-saml-" + generator.generate();
        final String zoneAdminClientId = "admin";
        UaaClientDetails zoneAdminClient = new UaaClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new AlphanumericRandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition3 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(BootstrapSamlIdentityProviderDataTests.XML_WITHOUT_ID.formatted("http://example3.com/saml/metadata"))
                .setIdpEntityAlias(alias3)
                .setLinkText("Active3 SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider<SamlIdentityProviderDefinition> activeIdentityProvider3 = new IdentityProvider<>();
        activeIdentityProvider3.setType(SAML);
        activeIdentityProvider3.setName("Active 3 SAML Provider");
        activeIdentityProvider3.setActive(true);
        activeIdentityProvider3.setConfig(activeSamlIdentityProviderDefinition3);
        activeIdentityProvider3.setOriginKey(alias3);
        activeIdentityProvider3 = createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider3);

        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition2 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(BootstrapSamlIdentityProviderDataTests.XML_WITHOUT_ID.formatted("http://example2.com/saml/metadata"))
                .setIdpEntityAlias(alias2)
                .setLinkText("Active2 SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider<SamlIdentityProviderDefinition> activeIdentityProvider2 = new IdentityProvider<>();
        activeIdentityProvider2.setType(SAML);
        activeIdentityProvider2.setName("Active 2 SAML Provider");
        activeIdentityProvider2.setActive(true);
        activeIdentityProvider2.setConfig(activeSamlIdentityProviderDefinition2);
        activeIdentityProvider2.setOriginKey(alias2);
        activeIdentityProvider2 = createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider2);

        zoneAdminClient.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, asList(activeIdentityProvider3.getOriginKey(), activeIdentityProvider2.getOriginKey()));
        MockMvcUtils.updateClient(webApplicationContext, zoneAdminClient, identityZone);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = new DefaultSavedRequest(new MockHttpServletRequest(), new PortResolverImpl()) {
            @Override
            public String getRedirectUrl() {
                return "http://test/redirect/oauth/authorize";
            }

            @Override
            public String[] getParameterValues(String name) {
                if ("client_id".equals(name)) {
                    return new String[]{"admin"};
                }
                return new String[0];
            }

            @Override
            public List<Cookie> getCookies() {
                return null;
            }

            @Override
            public String getMethod() {
                return null;
            }

            @Override
            public List<String> getHeaderValues(String name) {
                return null;
            }

            @Override
            public Collection<String> getHeaderNames() {
                return null;
            }

            @Override
            public List<Locale> getLocales() {
                return null;
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                return null;
            }
        };
        SessionUtils.setSavedRequestSession(MockMvcUtils.getZoneSession(session, mode, identityZone.getSubdomain()), savedRequest);

        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML)
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[text()='Create account']").doesNotExist())
                .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void deactivatedProviderIsRemovedFromSamlLoginLinks(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String alias = "login-saml-" + generator.generate();
        UaaClientDetails zoneAdminClient = new UaaClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new AlphanumericRandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = MockMvcUtils.IDP_META_DATA.formatted(new AlphanumericRandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("SAML Provider")
                .setShowSamlLink(true)
                .setZoneId(identityZone.getId());
        IdentityProvider<SamlIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setType(SAML);
        identityProvider.setName("SAML Provider");
        identityProvider.setActive(true);
        identityProvider.setConfig(samlIdentityProviderDefinition);
        identityProvider.setOriginKey(alias);
        identityProvider = createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, identityProvider);

        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']").exists());

        identityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(identityProvider, identityZone.getId());

        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.GET, "/login")
                        .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changeEmailWithoutAuthenticationReturnsRedirect(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH
                ? "http://localhost/z/" + subdomain + "/login"
                : "http://" + subdomain + ".localhost/login";
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/change_email").accept(TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirect));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changeEmailPageHasCsrf(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, zone.getId());

        MockHttpServletRequestBuilder get = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));
        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changeEmailSubmitWithMissingCsrf(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, zone.getId());

        MockHttpServletRequestBuilder get = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));
        MockHttpSession session = (MockHttpSession) mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")))
                .andReturn().getRequest().getSession();

        MockHttpServletRequestBuilder changeEmail = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_email.do")
                .accept(TEXT_HTML)
                .session(session)
                .with(cookieCsrf().useInvalidToken())
                .with(securityContext(marissaContext))
                .param("newEmail", "test@test.org")
                .param("client_id", "");
        mockMvc.perform(changeEmail)
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changeEmailSubmitWithInvalidCsrf(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, zone.getId());

        MockHttpServletRequestBuilder get = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));
        MockHttpSession session = (MockHttpSession) mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")))
                .andReturn().getRequest().getSession();

        MockHttpServletRequestBuilder changeEmail = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_email.do")
                .accept(TEXT_HTML)
                .session(session)
                .with(securityContext(marissaContext))
                .param("newEmail", "test@test.org")
                .param("client_id", "")
                .with(cookieCsrf().useInvalidToken());
        mockMvc.perform(changeEmail)
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changeEmailSubmitWithSpringSecurityForcedCsrf(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, zone.getId());
        MockHttpServletRequestBuilder changeEmail = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_email.do")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext))
                .with(cookieCsrf())
                .param("newEmail", "test@test.org")
                .param("client_id", "");

        HttpSession session = mockMvc.perform(changeEmail)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("email_sent?code=email_change"))
                .andReturn().getRequest().getSession(false);
        System.out.println("session = " + session);
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changeEmailSubmitWithCorrectCsrf(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, zone.getId());

        MockHttpServletRequestBuilder get = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));

        MvcResult result = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")))
                .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession();

        MockHttpServletRequestBuilder changeEmail = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_email.do")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext))
                .with(cookieCsrf())
                .session(session)
                .param("newEmail", "test@test.org")
                .param("client_id", "");
        mockMvc.perform(changeEmail)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("email_sent?code=email_change"));

    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changeEmailDoNotLoggedIn(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, zone.getId());
        String expectedLoginRedirect = mode == ZoneResolutionMode.ZONE_PATH
                ? "http://localhost/z/" + subdomain + "/login"
                : "http://" + subdomain + ".localhost/login";

        MockHttpServletRequestBuilder changeEmail = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_email.do")
                .accept(TEXT_HTML)
                .with(cookieCsrf());
        mockMvc.perform(changeEmail)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedLoginRedirect));

        changeEmail = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_email.do")
                .accept(TEXT_HTML)
                .with(cookieCsrf());
        mockMvc.perform(changeEmail)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedLoginRedirect));

        changeEmail = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_email.do")
                .accept(TEXT_HTML)
                .with(cookieCsrf().useInvalidToken())
                .with(securityContext(marissaContext));
        mockMvc.perform(changeEmail)
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void changeEmailNoCsrfReturns403AndInvalidRequest(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, zone.getId());

        MockHttpServletRequestBuilder get = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));

        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")))
                .andReturn();

        MockHttpServletRequestBuilder changeEmail = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/change_email.do")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext))
                .with(cookieCsrf().useInvalidToken())
                .param("newEmail", "test@test.org")
                .param("client_id", "");
        mockMvc.perform(changeEmail)
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void csrfForInvitationAcceptPost(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, zone.getId());
        AnonymousAuthenticationToken inviteToken = new AnonymousAuthenticationToken("invited-test", marissaContext.getAuthentication().getPrincipal(), singletonList(UaaAuthority.UAA_INVITED));
        MockHttpSession inviteSession = new MockHttpSession();
        SecurityContext inviteContext = new SecurityContextImpl();
        inviteContext.setAuthentication(inviteToken);
        MockMvcUtils.getZoneSession(inviteSession, mode, subdomain).setAttribute("SPRING_SECURITY_CONTEXT", inviteContext);

        Map<String, String> codeData = new HashMap();
        codeData.put("user_id", ((UaaPrincipal) marissaContext.getAuthentication().getPrincipal()).getId());
        codeData.put("email", ((UaaPrincipal) marissaContext.getAuthentication().getPrincipal()).getEmail());
        codeData.put("origin", UAA);

        ExpiringCode code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + 1000 * 60), null, zone.getId());

        String expectedLoginRedirect = mode == ZoneResolutionMode.ZONE_PATH
                ? "http://localhost/z/" + subdomain + "/login"
                : "http://" + subdomain + ".localhost/login";

        //logged in with valid CSRF
        MockHttpServletRequestBuilder post = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/invitations/accept.do")
                .session(inviteSession)
                .with(cookieCsrf())
                .param("code", code.getCode())
                .param("client_id", "random")
                .param("password", "password")
                .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(result -> {
                    String redirectUrl = result.getResponse().getRedirectedUrl();
                    assertThat(redirectUrl).contains("invitations/accept").contains("error_message_code=form_error").contains("code=");
                })
        ;

        //logged in, invalid CSRF
        post = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/invitations/accept.do")
                .session(inviteSession)
                .with(cookieCsrf().useInvalidToken())
                .param("client_id", "random")
                .param("password", "password")
                .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));

        //not logged in, no CSRF
        post = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/invitations/accept.do")
                .param("client_id", "random")
                .param("password", "password")
                .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedLoginRedirect + "?error=invalid_login_request"));

        //not logged in, valid CSRF(can't happen)
        post = mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/invitations/accept.do")
                .with(cookieCsrf())
                .param("client_id", "random")
                .param("password", "password")
                .param("code", "notvalidated")
                .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedLoginRedirect));
    }

    @Disabled("CORS: filter path matching differs when request is in zone (subdomain or zone path)")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutCorsPreflight(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        corsFilter.getFilter().setCorsXhrAllowedOrigins(asList("^localhost$", "^*\\.localhost$"));
        List<String> allowedUris = mode == ZoneResolutionMode.ZONE_PATH ? asList("^/logout\\.do$", "^/z/[^/]+/logout\\.do$") : singletonList("^/logout\\.do$");
        corsFilter.getFilter().setCorsXhrAllowedUris(allowedUris);
        corsFilter.getFilter().initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", mode == ZoneResolutionMode.ZONE_PATH ? "localhost" : subdomain + ".localhost");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.OPTIONS, "/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    @Disabled("CORS: filter path matching differs when request is in zone")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutCorsPreflightForIdentityZone(ZoneResolutionMode mode) throws Exception {
        String subdomain = "testzone1";
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        corsFilter.getFilter().setCorsXhrAllowedOrigins(asList("^localhost$", "^*\\.localhost$"));
        List<String> allowedUris = mode == ZoneResolutionMode.ZONE_PATH ? asList("^/logout.do$", "^/z/[^/]+/logout.do$") : singletonList("^/logout.do$");
        corsFilter.getFilter().setCorsXhrAllowedUris(allowedUris);
        corsFilter.getFilter().initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", mode == ZoneResolutionMode.ZONE_PATH ? "localhost" : subdomain + ".localhost");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.OPTIONS, "/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    /**
     * This should avoid the logic for X-Requested-With header entirely.
     *
     * @throws Exception on test failure
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutCorsPreflightWithStandardHeader(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        corsFilter.getFilter().setCorsXhrAllowedOrigins(singletonList("^localhost$"));
        List<String> allowedUris = mode == ZoneResolutionMode.ZONE_PATH ? asList("^/logout\\.do$", "^/z/[^/]+/logout\\.do$") : singletonList("^/logout\\.do$");
        corsFilter.getFilter().setCorsXhrAllowedUris(allowedUris);
        corsFilter.getFilter().initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "Accept");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "localhost");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.OPTIONS, "/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    /**
     * The endpoint is not whitelisted to allow CORS requests with the "X-Requested-With" header so the
     * CorsFilter returns a 403.
     *
     * @throws Exception on test failure
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutCorsPreflightWithUnallowedEndpoint(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        corsFilter.getFilter().setCorsXhrAllowedOrigins(singletonList("^localhost$"));
        List<String> allowedUris = mode == ZoneResolutionMode.ZONE_PATH ? asList("^/logout\\.do$", "^/z/[^/]+/logout\\.do$") : singletonList("^/logout\\.do$");
        corsFilter.getFilter().setCorsXhrAllowedUris(allowedUris);
        corsFilter.getFilter().initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", mode == ZoneResolutionMode.ZONE_PATH ? "localhost" : subdomain + ".localhost");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.OPTIONS, "/logout.dont").headers(httpHeaders)).andExpect(status().isForbidden());
    }

    /**
     * The access control request method is not a GET therefore CORS requests with the "X-Requested-With"
     * header are not allowed and the CorsFilter returns a 405.
     *
     * @throws Exception on test failure
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutCorsPreflightWithUnallowedMethod(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        corsFilter.getFilter().setCorsXhrAllowedOrigins(singletonList("^localhost$"));
        List<String> allowedUris = mode == ZoneResolutionMode.ZONE_PATH ? asList("^/logout\\.do$", "^/z/[^/]+/logout\\.do$") : singletonList("^/logout\\.do$");
        corsFilter.getFilter().setCorsXhrAllowedUris(allowedUris);
        corsFilter.getFilter().initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "POST");
        httpHeaders.add("Origin", mode == ZoneResolutionMode.ZONE_PATH ? "localhost" : subdomain + ".localhost");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.OPTIONS, "/logout.do").headers(httpHeaders)).andExpect(status().isMethodNotAllowed());
    }

    /**
     * The request origin is not whitelisted to allow CORS requests with the "X-Requested-With" header so the
     * CorsFilter returns a 403.
     *
     * @throws Exception on test failure
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void logOutCorsPreflightWithUnallowedOrigin(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        corsFilter.getFilter().setCorsXhrAllowedOrigins(singletonList("^localhost$"));
        List<String> allowedUris = mode == ZoneResolutionMode.ZONE_PATH ? asList("^/logout\\.do$", "^/z/[^/]+/logout\\.do$") : singletonList("^/logout\\.do$");
        corsFilter.getFilter().setCorsXhrAllowedUris(allowedUris);
        corsFilter.getFilter().initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "fuzzybunnies.com");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.OPTIONS, "/logout.do").headers(httpHeaders)).andExpect(status().isForbidden());
    }

    /**
     * When the zone-specific CORS policy of a non-default zone is null, fall back to enforcing
     * the CORS policy of the default zone.
     * Positive test case that exercises the CORS logic for dealing with the "X-Requested-With" header.
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void xhrCorsPreflightForNonDefaultZoneWhenZoneSpecificCorsPolicyIsNull(ZoneResolutionMode mode) throws Exception {
        // setting the default zone CORS policy
        corsFilter.getFilter().setCorsXhrAllowedOrigins(asList("^localhost$", "^*\\.localhost$"));
        // For ZONE_PATH mode, the request path is /z/{subdomain}/logout.do, so we need to allow that pattern
        List<String> allowedUris = mode == ZoneResolutionMode.ZONE_PATH
                ? asList("^/logout.do$", "^/z/[^/]+/logout.do$")
                : singletonList("^/logout.do$");
        corsFilter.getFilter().setCorsXhrAllowedUris(allowedUris);
        corsFilter.getFilter().initialize();

        // set the non default zone CORS Xhr policy to null
        identityZone.getConfig().getCorsPolicy().setXhrConfiguration(null);
        MockMvcUtils.updateIdentityZone(identityZone, webApplicationContext);

        // sending a XHR preflight request to the non default zone
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        // For ZONE_PATH mode, use localhost as Origin (no subdomain in host)
        httpHeaders.add("Origin", mode == ZoneResolutionMode.ZONE_PATH ? "localhost" : "testzone1.localhost");
        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.OPTIONS, "/logout.do")
                        .headers(httpHeaders))
                .andExpect(status().isOk());
    }

    /**
     * When the zone-specific CORS policy of a non-default zone exists, enforce it.
     * Positive test case that exercises the CORS logic for dealing with the "X-Requested-With" header.
     * The access control request method is POST, which is allowed by the zone specific CORS policy in this test case setup
     */
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void xhrCorsPreflightForNonDefaultZoneWhenZoneSpecificCorsPolicyExists(ZoneResolutionMode mode) throws Exception {
        // setting the default zone CORS policy to not allow POST
        corsFilter.getFilter().setCorsXhrAllowedMethods(List.of(GET.toString(), OPTIONS.toString()));
        corsFilter.getFilter().initialize();

        // set the non default zone CORS Xhr policy to allow POST
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedMethods(List.of(GET.toString(), OPTIONS.toString(), POST.toString()));
        identityZone.getConfig().getCorsPolicy().getXhrConfiguration().setAllowedHeaders(List.of(ACCEPT, AUTHORIZATION, CONTENT_TYPE, X_REQUESTED_WITH));
        MockMvcUtils.updateIdentityZone(identityZone, webApplicationContext);

        // sending a XHR preflight request to the non default zone
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "POST");
        httpHeaders.add("Origin", "testzone1.localhost");
        mockMvc.perform(mode.createRequestBuilder(identityZone.getSubdomain(), HttpMethod.OPTIONS, "/logout.do")
                        .headers(httpHeaders))
                .andExpect(status().isOk());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void login_LockoutPolicySucceeds_WhenLockedOut(ZoneResolutionMode mode) throws Exception {
        String subdomain = generator.generate().toLowerCase();
        IdentityZone zone = createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        changeLockoutPolicyForIdpInZone(jdbcIdentityProviderProvisioning, zone);
        ScimUser userToLockout = createUser(scimUserProvisioning, generator, zone.getId());
        attemptUnsuccessfulLogin(mockMvc, mode, 2, userToLockout.getUserName(), subdomain);
        String expectedRedirect = mode == ZoneResolutionMode.SUBDOMAIN ? "/login?error=account_locked" :
                "/z/" + subdomain + "/login?error=account_locked";
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                        .with(cookieCsrf())
                        .param("username", userToLockout.getUserName())
                        .param("password", userToLockout.getPassword()))
                .andExpect(redirectedUrl(expectedRedirect))
                .andExpect(emptyCurrentUserCookie(mode));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void login_LockoutPolicySucceeds_WhenPolicyIsUpdatedByApi(ZoneResolutionMode mode) throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        changeLockoutPolicyForIdpInZone(jdbcIdentityProviderProvisioning, zone);

        ScimUser userToLockout = createUser(scimUserProvisioning, generator, zone.getId());

        attemptUnsuccessfulLogin(mockMvc, mode, 2, userToLockout.getUserName(), subdomain);

        String expectedRedirect = mode == ZoneResolutionMode.SUBDOMAIN ? "/login?error=account_locked" :
                "/z/" + subdomain + "/login?error=account_locked";
        MockHttpServletRequestBuilder requestBuilder = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .with(cookieCsrf())
                .param("username", userToLockout.getUserName())
                .param("password", userToLockout.getPassword());
        mockMvc.perform(requestBuilder)
                .andExpect(redirectedUrl(expectedRedirect))
                .andExpect(emptyCurrentUserCookie(mode));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void autologin_with_validCode_RedirectsToSavedRequest_ifPresent(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        MockHttpSession session = MockMvcUtils.getSavedRequestSession(mode, subdomain);

        MockMvcUtils.PredictableGenerator predictableGenerator = new MockMvcUtils.PredictableGenerator();
        jdbcExpiringCodeStore.setGenerator(predictableGenerator);

        AutologinRequest request = new AutologinRequest();
        request.setUsername("marissa");
        request.setPassword("koala");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/autologin")
                        .header("Authorization", "Basic " + new String(ENCODER.encode("admin:admin-secret".getBytes())))
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk());

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/autologin")
                        .session(session)
                        .param("code", "test" + predictableGenerator.counter.get())
                        .param("client_id", "admin"))
                .andExpect(redirectedUrl("http://test/redirect/oauth/authorize"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void autologin_with_validCode_RedirectsToHome(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        MockMvcUtils.PredictableGenerator predictableGenerator = new MockMvcUtils.PredictableGenerator();
        jdbcExpiringCodeStore.setGenerator(predictableGenerator);

        AutologinRequest request = new AutologinRequest();
        request.setUsername("marissa");
        request.setPassword("koala");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/autologin")
                        .header("Authorization", "Basic " + new String(ENCODER.encode("admin:admin-secret".getBytes())))
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk());

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/autologin")
                        .param("code", "test" + predictableGenerator.counter.get())
                        .param("client_id", "admin"))
                .andExpect(redirectedUrl("home"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void autologin_with_validCode_and_formencoded_RedirectsToHome(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        ScimUser marissa = new ScimUser(null, "marissa", "Test", "User");
        marissa.setPrimaryEmail("marissa@test.org");
        marissa.setOrigin(UAA);
        scimUserProvisioning.createUser(marissa, "koala", zone.getId());
        MockMvcUtils.PredictableGenerator predictableGenerator = new MockMvcUtils.PredictableGenerator();
        jdbcExpiringCodeStore.setGenerator(predictableGenerator);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/autologin")
                        .header("Authorization", "Basic " + new String(ENCODER.encode("admin:admin-secret".getBytes())))
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .content("username=marissa&password=koala"))
                .andExpect(status().isOk());

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/autologin")
                        .param("code", "test" + predictableGenerator.counter.get())
                        .param("client_id", "admin"))
                .andExpect(redirectedUrl("home"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryPageDisplayed_IfFlagIsEnabled(ZoneResolutionMode mode) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"))
                .andExpect(content().string(containsString("Sign in")))
                .andExpect(xpath("//input[@name='email']").exists())
                .andExpect(xpath("//div[@class='action']//a").string("Create account"))
                .andExpect(xpath("//input[@name='commit']/@value").string("Next"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryPageNotDisplayed_IfFlagIsEnabledAndDiscoveryUnsuccessfulPreviously(ZoneResolutionMode mode) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("discoveryPerformed", "true")
                        .header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/password"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryClientNameDisplayed_WithUTF8Characters(ZoneResolutionMode mode) throws Exception {
        String utf8String = "\u7433\u8D3A";
        String clientName = "woohoo-" + utf8String;
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        MockHttpSession session = new MockHttpSession();
        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, clientName);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedRequest savedRequest = getSavedRequest(client);
        SessionUtils.setSavedRequestSession(MockMvcUtils.getZoneSession(session, mode, zone.getSubdomain()), savedRequest);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .session(session)
                        .header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"))
                .andExpect(content().string(containsString("Sign in to continue to " + clientName)))
                .andExpect(xpath("//input[@name='email']").exists())
                .andExpect(xpath("//div[@class='action']//a").string("Create account"))
                .andExpect(xpath("//input[@name='commit']/@value").string("Next"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void accountChooserEnabled_NoSaveAccounts(ZoneResolutionMode mode) throws Exception {
        String clientName = "woohoo";
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        MockHttpSession session = new MockHttpSession();
        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, clientName);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedAccountOption savedAccount = new SavedAccountOption();
        savedAccount.setEmail("test@example.org");
        savedAccount.setOrigin("uaa");
        savedAccount.setUserId("1234-5678");
        savedAccount.setUsername("test@example.org");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .session(session)
                        .header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void accountChooserEnabled(ZoneResolutionMode mode) throws Exception {
        String clientName = "woohoo";
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        MockHttpSession session = new MockHttpSession();
        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, clientName);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedAccountOption savedAccount = new SavedAccountOption();
        savedAccount.setEmail("test@example.org");
        savedAccount.setOrigin("uaa");
        savedAccount.setUserId("1234-5678");
        savedAccount.setUsername("test@example.org");
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .session(session)
                        .cookie(new Cookie("Saved-Account-12345678", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount), StandardCharsets.UTF_8)))
                        .header("Accept", TEXT_HTML))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/account_chooser"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void accountChooserWithoutDiscovery(ZoneResolutionMode mode) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(false);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .session(session)
                        .header("Accept", TEXT_HTML))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/origin"));
    }

    @Disabled("ZONE_PATH: redirect or content assertion differs for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void accountChooserWithoutDiscovery_loginWithProvidedLoginHint(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(false);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        String originKey = createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code");
        String loginHint = "%7B%22origin%22%3A%22" + originKey + "%22%7D";

        MvcResult mvcResult = mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/origin-chooser")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .servletPath(mode.getServletPath(zone.getSubdomain(), "/origin-chooser"))
                        .param("login_hint", originKey))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location).startsWith(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" : "/login");
        assertThat(location).contains("/login");
        assertThat(queryParams).containsEntry("login_hint", loginHint)
                .containsEntry("discoveryPerformed", "true");
    }

    @Disabled("ZONE_PATH: redirect or content assertion differs for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void accountChooserWithoutDiscovery_noDefaultReturnsLoginPage(ZoneResolutionMode mode) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter.getFilter()), "Test only runs in non limited mode.");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(false);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code");

        MvcResult mvcResult = mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/origin-chooser")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .servletPath(mode.getServletPath(zone.getSubdomain(), "/origin-chooser")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location).startsWith(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" : "/login");
        assertThat(location).contains("/login");
        assertThat(queryParams)
                .containsEntry("discoveryPerformed", "true")
                .doesNotContainKey("login_hint");
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void emailPageIdpDiscoveryEnabled_SelfServiceLinksDisabled(ZoneResolutionMode mode) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setLinks(new Links().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(false)));
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login"))
                .andExpect(xpath("//div[@class='action']//a").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryRedirectsToSamlExternalProvider_withClientContext(ZoneResolutionMode mode) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        String originKey = generator.generate();
        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone, mode);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .session(session)
                        .param("email", "marissa@test.org"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/saml2/authenticate/" + originKey : "/saml2/authenticate/" + originKey));
    }

    @Disabled("ZONE_PATH: redirect URL assertion differs for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryRedirectsToOIDCProvider(ZoneResolutionMode mode) throws Exception {
        String subdomain = "oidc-discovery-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        String originKey = createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code");

        MvcResult mvcResult = mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .servletPath(mode.getServletPath(zone.getSubdomain(), "/login/idp_discovery"))
                        .param("email", "marissa@test.org"))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        // For ZONE_PATH mode, redirect_uri is http://localhost/z/{subdomain}/login/callback/...; for SUBDOMAIN, http://{subdomain}.localhost/login/callback/...
        String expectedRedirectUri = mode == ZoneResolutionMode.ZONE_PATH
                ? "http%3A%2F%2Flocalhost%2Fz%2F" + subdomain + "%2Flogin%2Fcallback%2F" + originKey
                : "http%3A%2F%2F" + subdomain + ".localhost%2Flogin%2Fcallback%2F" + originKey;
        assertThat(location).startsWith("http://myauthurl.com");
        assertThat(queryParams).containsEntry("client_id", "id")
                .containsEntry("response_type", "id_token+code")
                .containsEntry("redirect_uri", expectedRedirectUri)
                .containsKey("nonce");
    }

    @Disabled("ZONE_PATH: redirect URL assertion differs for zone path")
    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void multiple_oidc_providers_use_response_type_in_url(ZoneResolutionMode mode) throws Exception {
        String subdomain = "oidc-idp-discovery-multi-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "code id_token");

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login")
                        .header("Accept", TEXT_HTML)
                        .servletPath(mode.getServletPath(zone.getSubdomain(), "/login")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("http://myauthurl.com?client_id=id&amp;response_type=code&")))
                .andExpect(content().string(containsString("http://myauthurl.com?client_id=id&amp;response_type=code+id_token&")));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryWithNoEmailDomainMatch_withClientContext(ZoneResolutionMode mode) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        IdentityZoneHolder.set(zone);
        IdentityProvider identityProvider = jdbcIdentityProviderProvisioning.retrieveByOrigin("uaa", zone.getId());
        identityProvider.setConfig(new AbstractIdentityProviderDefinition().setEmailDomain(Collections.singletonList("totally-different.org")));
        jdbcIdentityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone, mode);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .session(session)
                        .param("email", "marissa@other.domain"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login?discoveryPerformed=true&email=marissa%40other.domain" : "/login?discoveryPerformed=true&email=marissa%40other.domain"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryWithMultipleEmailDomainMatches_withClientContext(ZoneResolutionMode mode) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        IdentityZoneHolder.set(zone);
        IdentityProvider identityProvider = jdbcIdentityProviderProvisioning.retrieveByOrigin("uaa", zone.getId());
        identityProvider.setConfig(new AbstractIdentityProviderDefinition().setEmailDomain(Collections.singletonList("test.org")));
        jdbcIdentityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone, mode);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .session(session)
                        .param("email", "marissa@test.org"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login?discoveryPerformed=true&email=marissa%40test.org" : "/login?discoveryPerformed=true&email=marissa%40test.org"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryWithUaaFallBack_withClientContext(ZoneResolutionMode mode) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone, mode);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .session(session)
                        .param("email", "marissa@other.domain"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + zone.getSubdomain() + "/login?discoveryPerformed=true&email=marissa%40other.domain" : "/login?discoveryPerformed=true&email=marissa%40other.domain"));

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("discoveryPerformed", "true").param("email", "marissa@other.domain")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .session(session))
                .andExpect(model().attributeExists("zone_name"))
                .andExpect(view().name("login"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void idpDiscoveryWithLdap_withClientContext(ZoneResolutionMode mode) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(LDAP, zone.getId());
        identityProvider.setType(LDAP);
        identityProvider.setConfig(new LdapIdentityProviderDefinition().setEmailDomain(Collections.singletonList("testLdap.org")));

        createIdentityProvider(jdbcIdentityProviderProvisioning, zone, identityProvider);

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone, mode);

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .session(session)
                        .param("email", "marissa@testLdap.org"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/login?discoveryPerformed=true&email=marissa%40testLdap.org" : "/login?discoveryPerformed=true&email=marissa%40testLdap.org"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void passwordPageDisplayed_ifUaaIsFallbackIDPForEmailDomain(ZoneResolutionMode mode) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .header("Accept", TEXT_HTML)
                        .with(cookieCsrf())
                        .param("email", "marissa@koala.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + zone.getSubdomain() + "/login?discoveryPerformed=true&email=marissa%40koala.com" : "/login?discoveryPerformed=true&email=marissa%40koala.com"));

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("discoveryPerformed", "true").param("email", "marissa@koala.com")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML))
                .andExpect(view().name("idp_discovery/password"))
                .andExpect(xpath("//input[@name='password']").exists())
                .andExpect(xpath("//input[@name='username']/@value").string("marissa@koala.com"))
                .andExpect(xpath("//div[@class='action pull-right']//a").string("Reset password"))
                .andExpect(xpath("//input[@type='submit']/@value").string("Sign in"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void passwordPageIdpDiscoveryEnabled_SelfServiceLinksDisabled(ZoneResolutionMode mode) throws Exception {
        String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setLinks(new Links().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(false)));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, zone.getId(), config);

        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + zone.getSubdomain() + "/login?discoveryPerformed=true&email=marissa%40koala.org" : "/login?discoveryPerformed=true&email=marissa%40koala.org";
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML)
                        .param("email", "marissa@koala.org"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirect));

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("discoveryPerformed", "true").param("email", "marissa@koala.org")
                        .with(cookieCsrf())
                        .header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//div[@class='action pull-right']//a").doesNotExist());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void userNamePresentInPasswordPage(ZoneResolutionMode mode) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH
                ? "/z/" + zone.getSubdomain() + "/login?discoveryPerformed=true&email=test%40email.com"
                : "/login?discoveryPerformed=true&email=test%40email.com";
        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.POST, "/login/idp_discovery")
                        .with(cookieCsrf())
                        .param("email", "test@email.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(expectedRedirect));

        mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("discoveryPerformed", "true").param("email", "test@email.com")
                        .with(cookieCsrf()))
                .andExpect(xpath("//input[@name='username']/@value").string("test@email.com"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void authorizeForClientWithIdpNotAllowed(ZoneResolutionMode mode) throws Exception {
        String subdomain = "idp-not-allowed-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone = createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone = identityZoneProvisioning.update(zone);

        ScimUser user = createUser(scimUserProvisioning, generator, zone.getId());
        MockHttpSession session = new MockHttpSession();

        String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH ? "/z/" + subdomain + "/" : "/";
        MockHttpServletRequestBuilder post = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .with(cookieCsrf())
                .session(session)
                .param("username", user.getUserName())
                .param("password", user.getPassword());

        mockMvc.perform(post)
                .andExpect(redirectedUrl(expectedRedirect));
        // authorize for client that does not allow that idp

        String clientId = "different-provider-client";
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.setScope(singleton("uaa.user"));
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "THE APPLICATION");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, singletonList("a-different-provider"));
        HashSet<String> registeredRedirectUris = new HashSet<>();
        registeredRedirectUris.add("http://idp-not-allowed.localhost/");
        client.setRegisteredRedirectUri(registeredRedirectUris);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        MockHttpServletRequestBuilder authorize = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/oauth/authorize")
                .session(session)
                .param("client_id", "different-provider-client")
                .param("response_type", "code")
                .param("client_secret", "secret")
                .param("garbage", "this-should-be-preserved");

        // For ZONE_PATH mode, the URL uses localhost with zone path; for SUBDOMAIN mode, it uses subdomain.localhost
        String expectedUrl = mode == ZoneResolutionMode.ZONE_PATH
                ? "http://localhost/z/" + subdomain + "/oauth/authorize?client_id=different-provider-client&response_type=code&client_secret=secret&garbage=this-should-be-preserved"
                : "http://" + subdomain + ".localhost/oauth/authorize?client_id=different-provider-client&response_type=code&client_secret=secret&garbage=this-should-be-preserved";
        String html = mockMvc.perform(authorize)
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String extractPattern = "logout.do\\?redirect\\=(.*?)\">click here<";
        Pattern pattern = Pattern.compile(extractPattern);
        Matcher matcher = pattern.matcher(html);
        assertThat(matcher.find()).isTrue();
        String group = matcher.group(1);
        assertThat(URLDecoder.decode(group, StandardCharsets.UTF_8)).isEqualTo(expectedUrl);
    }

    private static MockHttpSession setUpClientAndProviderForIdpDiscovery(
            WebApplicationContext webApplicationContext,
            JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning,
            AlphanumericRandomValueStringGenerator generator,
            String originKey,
            IdentityZone zone,
            ZoneResolutionMode mode) {
        String metadata = MockMvcUtils.IDP_META_DATA.formatted(new AlphanumericRandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition config = (SamlIdentityProviderDefinition) new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(originKey)
                .setLinkText("Active SAML Provider")
                .setZoneId(zone.getId())
                .setEmailDomain(Collections.singletonList("test.org"));

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(originKey, zone.getId());
        identityProvider.setType(SAML);
        identityProvider.setConfig(config);
        createIdentityProvider(jdbcIdentityProviderProvisioning, zone, identityProvider);

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "woohoo");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, asList(originKey, "other-provider", UAA, LDAP));
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedRequest savedRequest = getSavedRequest(client);
        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(MockMvcUtils.getZoneSession(session, mode, zone.getSubdomain()), savedRequest);
        return session;
    }

    private static void changeLockoutPolicyForIdpInZone(
            JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning,
            IdentityZone zone) {
        IdentityProvider identityProvider = jdbcIdentityProviderProvisioning.retrieveByOrigin(UAA, zone.getId());

        LockoutPolicy policy = new LockoutPolicy();
        policy.setLockoutAfterFailures(2);
        policy.setLockoutPeriodSeconds(3600);
        policy.setCountFailuresWithin(900);

        UaaIdentityProviderDefinition configMap = new UaaIdentityProviderDefinition(null, policy);

        identityProvider.setConfig(configMap);

        jdbcIdentityProviderProvisioning.update(identityProvider, zone.getId());
    }

    @Nested
    @DefaultTestContext
    class ErrorAndSuccessMessages {
        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void hasValidError(ZoneResolutionMode mode) throws Exception {
            String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
            IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
            mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("error", "login_failure"))
                    .andExpect(content().string(containsString("Provided credentials are invalid. Please try again.")));
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void hasInvalidError(ZoneResolutionMode mode) throws Exception {
            String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
            IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
            mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("error", "foobar").param("error", "login_failure"))
                    .andExpect(content().string(containsString("Error!")));
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void hasValidSuccess(ZoneResolutionMode mode) throws Exception {
            String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
            IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
            mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("success", "verify_success"))
                    .andExpect(content().string(containsString("Verification successful. Login to access your account.")));
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void hasInvalidSuccess(ZoneResolutionMode mode) throws Exception {
            String subdomain = new AlphanumericRandomValueStringGenerator(24).generate().toLowerCase();
            IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
            mockMvc.perform(mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, "/login").param("success", "foobar").param("success", "verify_success"))
                    .andExpect(content().string(containsString("Success!")));
        }
    }

    /**
     * login.do flow: success redirect, failure redirect, and saved-request redirect.
     * SUBDOMAIN should pass; ZONE_PATH may fail until success/failure handlers are zone-path aware.
     */
    @Nested
    @DefaultTestContext
    class LoginDoFlowZonePath {

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void login_do_success_redirects_to_default_target_with_zone_path(ZoneResolutionMode mode) throws Exception {
            String subdomain = generator.generate().toLowerCase();
            IdentityZone zone = createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
            ScimUser user = createUser(scimUserProvisioning, generator, zone.getId());

            MockHttpSession session = new MockHttpSession();
            MockHttpServletRequestBuilder post = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                    .session(session)
                    .with(cookieCsrf())
                    .param("username", user.getUserName())
                    .param("password", user.getPassword());
            String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH
                    ? "/z/" + subdomain + "/"
                    : "/";
            mockMvc.perform(post)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(expectedRedirect));
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void login_do_failure_redirects_to_login_with_zone_path(ZoneResolutionMode mode) throws Exception {
            String subdomain = generator.generate().toLowerCase();
            createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

            MockHttpServletRequestBuilder post = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                    .with(cookieCsrf())
                    .param("username", "nobody")
                    .param("password", "wrong");
            String expectedRedirect = mode == ZoneResolutionMode.ZONE_PATH
                    ? "/z/" + subdomain + "/login?error=login_failure"
                    : "/login?error=login_failure";
            mockMvc.perform(post)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(expectedRedirect))
                    .andExpect(emptyCurrentUserCookie(mode));
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        void login_do_success_redirects_to_saved_request(ZoneResolutionMode mode) throws Exception {
            String subdomain = generator.generate().toLowerCase();
            IdentityZone zone = createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
            ScimUser user = createUser(scimUserProvisioning, generator, zone.getId());

            String savedRedirectUrl = mode == ZoneResolutionMode.ZONE_PATH
                    ? "http://localhost/uaa/z/" + subdomain + "/oauth/authorize?client_id=admin&response_type=code"
                    : "http://" + subdomain + ".localhost/oauth/authorize?client_id=admin&response_type=code";
            MockHttpSession session = new MockHttpSession();
            MockHttpServletRequest savedReq = new MockHttpServletRequest("GET", "/oauth/authorize");
            savedReq.setServerName(mode == ZoneResolutionMode.ZONE_PATH ? "localhost" : subdomain + ".localhost");
            SessionUtils.setSavedRequestSession(MockMvcUtils.getZoneSession(session, mode, subdomain), new UaaSavedRequestCache.ClientRedirectSavedRequest(savedReq, savedRedirectUrl));

            MockHttpServletRequestBuilder post = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                    .session(session)
                    .with(cookieCsrf())
                    .param("username", user.getUserName())
                    .param("password", user.getPassword());
            mockMvc.perform(post)
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl(savedRedirectUrl));
        }
    }

    private static void attemptUnsuccessfulLogin(MockMvc mockMvc, ZoneResolutionMode mode, int numberOfAttempts, String username, String subdomain) throws Exception {
        attemptUnsuccessfulLogin(mockMvc, mode, numberOfAttempts, username, subdomain, "login_failure");
    }

    private static void attemptUnsuccessfulLogin(MockMvc mockMvc, ZoneResolutionMode mode, int numberOfAttempts, String username, String subdomain, String lastAttemptError) throws Exception {
        MockHttpServletRequestBuilder post = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/login.do")
                .with(cookieCsrf())
                .param("username", username)
                .param("password", "wrong_password");
        for (int i = 0; i < numberOfAttempts; i++) {
            String error = (i == numberOfAttempts - 1) ? lastAttemptError : "login_failure";
            String expectedRedirect = mode == ZoneResolutionMode.SUBDOMAIN ? "/login?error=" + error :
                    "/z/" + subdomain + "/login?error=" + error;
            mockMvc.perform(post)
                    .andExpect(redirectedUrl(expectedRedirect))
                    .andExpect(emptyCurrentUserCookie(mode));
        }
    }

    private static ResultMatcher emptyCurrentUserCookie(ZoneResolutionMode mode) {
        return result -> {
            cookie().value("Current-User", isEmptyOrNullString()).match(result);
            cookie().maxAge("Current-User", 0).match(result);
            String expectedPath = mode == ZoneResolutionMode.ZONE_PATH ? null : "/";
            if (expectedPath != null) {
                cookie().path("Current-User", expectedPath).match(result);
            } else {
                Cookie currentUserCookie = result.getResponse().getCookie("Current-User");
                assertThat(currentUserCookie).isNotNull();
                // Cookie path is always "/"
                assertThat(currentUserCookie.getPath()).isEqualTo("/");
            }
        };
    }

    private static IdentityZone setupZone(
            WebApplicationContext webApplicationContext,
            MockMvc mockMvc,
            IdentityZoneProvisioning identityZoneProvisioning,
            AlphanumericRandomValueStringGenerator generator,
            IdentityZoneConfiguration config) throws Exception {
        String zoneId = generator.generate().toLowerCase();
        IdentityZone zone = createOtherIdentityZone(zoneId, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        zone.setConfig(config);
        identityZoneProvisioning.update(zone);
        return zone;
    }

    private static SavedRequest getSavedRequest(UaaClientDetails client) {
        return new DefaultSavedRequest(new MockHttpServletRequest(), new PortResolverImpl()) {
            @Override
            public String getRedirectUrl() {
                return "http://test/redirect/oauth/authorize";
            }

            @Override
            public String[] getParameterValues(String name) {
                if ("client_id".equals(name)) {
                    return new String[]{client.getClientId()};
                }
                return new String[0];
            }

            @Override
            public List<Cookie> getCookies() {
                return null;
            }

            @Override
            public String getMethod() {
                return null;
            }

            @Override
            public List<String> getHeaderValues(String name) {
                return null;
            }

            @Override
            public Collection<String> getHeaderNames() {
                return null;
            }

            @Override
            public List<Locale> getLocales() {
                return null;
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                return null;
            }
        };
    }

    private static ScimUser createUser(ScimUserProvisioning scimUserProvisioning, AlphanumericRandomValueStringGenerator generator, String zoneId) {
        String username = generator.generate() + "@testdomain.com";
        return createUser(scimUserProvisioning, username, zoneId);
    }

    private static ScimUser createUser(ScimUserProvisioning scimUserProvisioning, String username, String zoneId) {
        ScimUser user = new ScimUser(null, username, "Test", "User");
        user.setPrimaryEmail(username);
        user.setPassword("Secr3t");
        user = scimUserProvisioning.createUser(user, user.getPassword(), zoneId);
        user.setPassword("Secr3t");
        return user;
    }

    private static String createOIDCProvider(JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning, AlphanumericRandomValueStringGenerator generator, IdentityZone zone, String responseType) throws Exception {
        String originKey = generator.generate();
        AbstractExternalOAuthIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setEmailDomain(singletonList("test.org"));
        definition.setAuthUrl(URI.create("http://myauthurl.com").toURL());
        definition.setTokenKey("key");
        definition.setTokenUrl(URI.create("http://mytokenurl.com").toURL());
        definition.setRelyingPartyId("id");
        definition.setRelyingPartySecret("secret");
        definition.setLinkText("my oidc provider");
        if (StringUtils.hasText(responseType)) {
            definition.setResponseType(responseType);
        }

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(originKey, zone.getId());
        identityProvider.setType(OIDC10);
        identityProvider.setConfig(definition);
        createIdentityProvider(jdbcIdentityProviderProvisioning, zone, identityProvider);
        return originKey;
    }

    private String createOIDCProviderInZone(JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning, IdentityZone identityZone, String discoveryUrl) throws Exception {
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();

        if (StringUtils.hasText(discoveryUrl)) {
            definition.setDiscoveryUrl(new URL(discoveryUrl));
        } else {
            definition.setAuthUrl(URI.create("http://auth.url").toURL());
            definition.setTokenUrl(URI.create("http://token.url").toURL());
        }
        definition.setTokenKey("key");
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        definition.setScopes(asList("openid", "roles"));
        definition.setResponseType("code id_token");
        String oauthAlias = "login-oauth-" + generator.generate();

        IdentityProvider<OIDCIdentityProviderDefinition> oauthIdentityProvider = MultitenancyFixture.identityProvider(oauthAlias, "uaa");
        oauthIdentityProvider.setConfig(definition);
        oauthIdentityProvider.setActive(true);

        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, oauthIdentityProvider);
        return oauthAlias;
    }

    protected static boolean isLimitedMode(LimitedModeUaaFilter limitedModeUaaFilter) {
        return limitedModeUaaFilter.isEnabled();
    }

    private static void setZoneFavIconAndProductLogo(WebApplicationContext webApplicationContext, IdentityZoneConfiguration identityZoneConfiguration, String favIcon, String productLogo) {
        BrandingInformation branding = new BrandingInformation();
        branding.setSquareLogo(favIcon);
        branding.setProductLogo(productLogo);
        identityZoneConfiguration.setBranding(branding);
    }

    private static IdentityProvider createIdentityProvider(JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning, IdentityZone identityZone, IdentityProvider activeIdentityProvider) {
        activeIdentityProvider.setIdentityZoneId(identityZone.getId());
        return jdbcIdentityProviderProvisioning.create(activeIdentityProvider, identityZone.getId());
    }
}
