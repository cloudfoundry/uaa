package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
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
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
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
import static java.util.Collections.EMPTY_LIST;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.constructGoogleMfaProvider;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createOtherIdentityZone;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getMarissaSecurityContext;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUaaSecurityContext;
import static org.cloudfoundry.identity.uaa.util.SessionUtils.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZone.getUaa;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@DefaultTestContext
@DirtiesContext
public class LoginMockMvcTests {

    private WebApplicationContext webApplicationContext;

    private RandomValueStringGenerator generator;

    private IdentityZoneConfiguration identityZoneConfiguration;
    private IdentityZone identityZone;
    private MockMvc mockMvc;
    private File originalLimitedModeStatusFile;
    private LimitedModeUaaFilter limitedModeUaaFilter;

    @MockBean
    OidcMetadataFetcher oidcMetadataFetcher;

    @BeforeEach
    void setUpContext(
            @Autowired WebApplicationContext webApplicationContext,
            @Autowired MockMvc mockMvc,
            @Autowired IdentityZoneProvisioning identityZoneProvisioning,
            @Autowired LimitedModeUaaFilter limitedModeUaaFilter
    ) throws Exception {
        generator = new RandomValueStringGenerator();
        this.webApplicationContext = webApplicationContext;
        this.mockMvc = mockMvc;
        this.limitedModeUaaFilter = limitedModeUaaFilter;
        SecurityContextHolder.clearContext();

        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        identityZoneConfiguration = identityZoneProvisioning.retrieve(IdentityZone.getUaaZoneId()).getConfig();
        IdentityZoneHolder.setProvisioning(identityZoneProvisioning);

        String subdomain = new RandomValueStringGenerator(24).generate().toLowerCase();
        identityZone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        MfaProvider mfaProvider = constructGoogleMfaProvider();
        mfaProvider = JsonUtils.readValue(mockMvc.perform(
                post("/mfa-providers")
                        .header("X-Identity-Zone-Id", identityZone.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsByteArray(), MfaProvider.class);

        identityZone.getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.updateIdentityZone(identityZone, webApplicationContext);

        originalLimitedModeStatusFile = MockMvcUtils.getLimitedModeStatusFile(webApplicationContext);
        MockMvcUtils.resetLimitedModeStatusFile(webApplicationContext, null);
        assertFalse(isLimitedMode(limitedModeUaaFilter));
    }

    @AfterEach
    void resetGenerator(
            @Autowired JdbcExpiringCodeStore jdbcExpiringCodeStore,
            @Autowired LoginInfoEndpoint loginInfoEndpoint
    ) {
        jdbcExpiringCodeStore.setGenerator(new RandomValueStringGenerator(24));
    }

    @AfterEach
    void tearDown(@Autowired IdentityZoneConfigurationBootstrap identityZoneConfigurationBootstrap) throws Exception {
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), true);
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
            RandomValueStringGenerator generator,
            String originKey,
            IdentityZone zone, List<String> allowedProviders) {

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
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
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, allowedProviders);

        MockMvcUtils.createClient(webApplicationContext, client, zone);
        SavedRequest savedRequest = getSavedRequest(client);

        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        return session;
    }

    private void expect_idp_discovery(
            JdbcIdentityProviderProvisioning identityProviderProvisioning,
            JdbcIdentityZoneProvisioning identityZoneProvisioning,
            List<String> allowedProviders
    ) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);

        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        String originKey = "fake-origin-key";
        allowedProviders.add(originKey);

        MockHttpSession session = configure_UAA_for_idp_discovery(webApplicationContext, identityProviderProvisioning, generator, originKey, zone, allowedProviders);

        mockMvc.perform(get("/login")
                .session(session)
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"))
                .andExpect(xpath("//input[@name='email']").exists());
    }

    @Test
    void access_discovery_when_expected(
            @Autowired JdbcIdentityProviderProvisioning identityProviderProvisioning,
            @Autowired JdbcIdentityZoneProvisioning identityZoneProvisioning) throws Exception {

        List<List<String>> allowedProvidersPermutations = new ArrayList<>();
        allowedProvidersPermutations.add(new ArrayList<>(asList(UAA, LDAP, SAML))); // Model should not contain a login hint if we allow both UAA and LDAP
        allowedProvidersPermutations.add(new ArrayList<>(asList(UAA, LDAP      ))); // Model should not contain a login hint if we allow both UAA and LDAP
        allowedProvidersPermutations.add(new ArrayList<>(asList(UAA,       SAML))); // Model should contain a login hint if we exclude LDAP from allowed providers
        allowedProvidersPermutations.add(new ArrayList<>(asList(     LDAP, SAML))); // Model should contain a login hint if we exclude UAA from allowed providers

        allowedProvidersPermutations.add(new ArrayList<>(singletonList(UAA)));  // Model should contain a login hint if we exclude LDAP from allowed providers
        allowedProvidersPermutations.add(new ArrayList<>(singletonList(LDAP))); // Model should contain a login hint if we exclude UAA from allowed providers

        for (List<String> allowedProviders : allowedProvidersPermutations) {
            expect_idp_discovery(identityProviderProvisioning, identityZoneProvisioning, allowedProviders);
        }
    }

    @Test
    void redirect_when_only_saml_allowed(
            @Autowired JdbcIdentityProviderProvisioning identityProviderProvisioning,
            @Autowired JdbcIdentityZoneProvisioning identityZoneProvisioning) throws Exception {

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
                new ArrayList<>(asList(originKey, SAML)));

        mockMvc.perform(get("/login")
                .session(session)
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void access_login_page_while_logged_in() throws Exception {
        SecurityContext securityContext = MockMvcUtils.getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());
        mockMvc.perform(
                get("/login")
                        .header("Accept", MediaType.TEXT_HTML_VALUE)
                        .with(securityContext(securityContext))
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/home"));
    }

    @Test
    void invalid_accept_media_type() throws Exception {
        mockMvc.perform(
                get("/login")
                        .header("Accept", MediaType.TEXT_XML_VALUE)
        )
                .andExpect(status().isNotAcceptable());
    }

    @Test
    void testLogin() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/forgot_password")))
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "/create_account")))
                .andExpect(model().attributeExists("prompts"))
                .andExpect(content().string(containsString("/create_account")));
    }

    @Test
    void testLoginMfaRedirect(
            @Autowired ScimUserProvisioning scimUserProvisioning
    ) throws Exception {
        MockHttpSession session = new MockHttpSession();

        ScimUser user = createUser(scimUserProvisioning, generator, identityZone.getId());

        mockMvc.perform(post("/login.do")
                .with(cookieCsrf())
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
                .session(session)
                .param("username", user.getUserName())
                .param("password", user.getPassword()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));

        mockMvc.perform(get("/")
                .with(cookieCsrf())
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
                .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login/mfa/register"));
    }

    IdentityZone createZoneLinksZone() throws Exception {
        String subdomain = new RandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        zone.getConfig().getLinks().setSelfService(new Links.SelfService().setPasswd(null).setSignup(null));
        return MockMvcUtils.updateIdentityZone(zone, webApplicationContext);
    }

    @Test
    void self_service_zone_variable_links(
            @Autowired LoginInfoEndpoint loginInfoEndpoint
    ) throws Exception {
        IdentityZone zone = createZoneLinksZone();

        mockMvc.perform(
                get("/login")
                        .header("Host", zone.getSubdomain() + ".localhost")
        )
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/forgot_password")))
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "/create_account")))
                .andExpect(content().string(containsString("/create_account")));

        ReflectionTestUtils.setField(loginInfoEndpoint, "globalLinks", new Links().setSelfService(
                new Links.SelfService()
                        .setPasswd("/passwd?id={zone.id}")
                        .setSignup("/signup?subdomain={zone.subdomain}")
        ));

        mockMvc.perform(
                get("/login")
                        .header("Host", zone.getSubdomain() + ".localhost")
        )
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
        mockMvc.perform(
                get("/login")
                        .header("Host", zone.getSubdomain() + ".localhost")
        )
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/local_passwd?id=" + zone.getId())))
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "/local_signup?subdomain=" + zone.getSubdomain())))
                .andExpect(content().string(containsString("/local_passwd?id=" + zone.getId())))
                .andExpect(content().string(containsString("/local_signup?subdomain=" + zone.getSubdomain())));

    }

    @Test
    void global_zone_variable_home_redirect(
            @Autowired @Qualifier("globalLinks") Links globalLinks,
            @Autowired ScimUserProvisioning scimUserProvisioning
    ) throws Exception {

        IdentityZone zone = createZoneLinksZone();
        ScimUser marissa = createUser(scimUserProvisioning, generator, zone.getId());

        mockMvc.perform(
                get("/")
                        .with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone.getId())))
                        .header("Host", zone.getSubdomain() + ".localhost")
        )
                .andDo(print())
                .andExpect(status().isOk());

        globalLinks.setHomeRedirect("http://{zone.subdomain}.redirect.to/z/{zone.id}");

        mockMvc.perform(
                get("/")
                        .with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone.getId())))
                        .header("Host", zone.getSubdomain() + ".localhost")
        )
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://" + zone.getSubdomain() + ".redirect.to/z/" + zone.getId()));

        zone.getConfig().getLinks().setHomeRedirect("http://configured.{zone.subdomain}.redirect.to/z/{zone.id}");
        zone = MockMvcUtils.updateIdentityZone(zone, webApplicationContext);
        mockMvc.perform(
                get("/")
                        .with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone.getId())))
                        .header("Host", zone.getSubdomain() + ".localhost")
        )
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://configured." + zone.getSubdomain() + ".redirect.to/z/" + zone.getId()));
    }

    @Test
    void testLogin_Csrf_MaxAge() throws Exception {
        mockMvc
                .perform(
                        get("/login"))
                .andExpect(status().isOk())
                .andExpect(cookie().maxAge(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, CookieBasedCsrfTokenRepository.DEFAULT_COOKIE_MAX_AGE));
    }

    @Test
    void testLogin_Csrf_Reset_On_Refresh() throws Exception {
        MvcResult mvcResult = mockMvc
                .perform(
                        get("/login"))
                .andReturn();
        Cookie csrf1 = mvcResult.getResponse().getCookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);

        mvcResult = mockMvc
                .perform(
                        get("/login")
                                .cookie(csrf1))
                .andReturn();
        Cookie csrf2 = mvcResult.getResponse().getCookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME);
        assertNotNull(csrf2);
        assertNotEquals(csrf1.getValue(), csrf2.getValue());
    }

    @Test
    void testLoginPageReloadOnCsrfExpiry(
            @Autowired CookieBasedCsrfTokenRepository cookieBasedCsrfTokenRepository
    ) throws Exception {
        cookieBasedCsrfTokenRepository.setCookieMaxAge(3);

        MvcResult mvcResult = mockMvc
                .perform(get("/login"))
                .andReturn();
        assertThat("", mvcResult.getResponse().getContentAsString(), containsString("http-equiv=\"refresh\" content=\"3\""));
        cookieBasedCsrfTokenRepository.setCookieMaxAge(CookieBasedCsrfTokenRepository.DEFAULT_COOKIE_MAX_AGE);
    }

    @Test
    void test_cookie_csrf(
            @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning
    ) throws Exception {
        MockHttpSession session = new MockHttpSession();

        MockHttpServletRequestBuilder invalidPost = post("/login.do")
                .session(session)
                .param("username", "marissa")
                .param("password", "koala");

        mockMvc.perform(invalidPost)
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login?error=invalid_login_request"));

        session = new MockHttpSession();
        String csrfValue = "12345";
        Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrfValue);

        mockMvc.perform(
                invalidPost
                        .cookie(cookie)
                        .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "other-value")
        )
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login?error=invalid_login_request"));

        MockHttpServletRequestBuilder validPost = post("/uaa/login.do")
                .session(session)
                .contextPath("/uaa")
                .param("username", "marissa")
                .param("password", "koala")
                .cookie(cookie)
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrfValue);
        mockMvc.perform(validPost)
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/"));
    }

    @Test
    void test_case_insensitive_login(
            @Autowired ScimUserProvisioning scimUserProvisioning
    ) throws Exception {
        String username = "mixed-CASE-USER-" + generator.generate() + "@testdomain.com";
        ScimUser user = createUser(scimUserProvisioning, username, IdentityZone.getUaaZoneId());
        assertEquals(username, user.getUserName());
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("username", user.getUserName())
                .param("password", user.getPassword());

        mockMvc.perform(loginPost)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"username\":\"" + user.getUserName())))
                .andExpect(content().string(containsString("\"email\":\"" + user.getPrimaryEmail())));

        loginPost = post("/authenticate")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .param("username", user.getUserName().toUpperCase())
                .param("password", user.getPassword());

        mockMvc.perform(loginPost)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"username\":\"" + user.getUserName())))
                .andExpect(content().string(containsString("\"email\":\"" + user.getPrimaryEmail())));
    }

    @Test
    void test_previous_login_time_upon_authentication(
            @Autowired ScimUserProvisioning scimUserProvisioning
    ) throws Exception {
        ScimUser user = createUser(scimUserProvisioning, generator, IdentityZone.getUaaZoneId());
        MockHttpSession session = new MockHttpSession();
        long beforeAuthTime = System.currentTimeMillis();
        mockMvc.perform(post("/uaa/login.do")
                .session(session)
                .with(cookieCsrf())
                .contextPath("/uaa")
                .param("username", user.getUserName())
                .param("password", user.getPassword()));
        long afterAuthTime = System.currentTimeMillis();
        SecurityContext securityContext = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNull(((UaaAuthentication) securityContext.getAuthentication()).getLastLoginSuccessTime());
        session = new MockHttpSession();

        mockMvc.perform(post("/uaa/login.do")
                .session(session)
                .with(cookieCsrf())
                .contextPath("/uaa")
                .param("username", user.getUserName())
                .param("password", user.getPassword()));
        securityContext = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

        Long lastLoginTime = ((UaaAuthentication) securityContext.getAuthentication()).getLastLoginSuccessTime();
        assertThat(lastLoginTime, greaterThanOrEqualTo(beforeAuthTime));
        assertThat(lastLoginTime, lessThanOrEqualTo(afterAuthTime));

    }

    @Test
    void testLogin_Post_When_DisableInternalUserManagement_Is_True(
            @Autowired ScimUserProvisioning scimUserProvisioning
    ) throws Exception {
        ScimUser user = createUser(scimUserProvisioning, generator, IdentityZone.getUaaZoneId());
        MockMvcUtils.setDisableInternalAuth(webApplicationContext, IdentityZone.getUaaZoneId(), true);
        try {
            mockMvc.perform(post("/login.do")
                    .with(cookieCsrf())
                    .param("username", user.getUserName())
                    .param("password", user.getPassword()))
                    .andExpect(redirectedUrl("/login?error=login_failure"));
        } finally {
            MockMvcUtils.setDisableInternalAuth(webApplicationContext, IdentityZone.getUaaZoneId(), false);
        }
        mockMvc.perform(post("/uaa/login.do")
                .with(cookieCsrf())
                .contextPath("/uaa")
                .param("username", user.getUserName())
                .param("password", user.getPassword()))
                .andDo(print())
                .andExpect(redirectedUrl("/uaa/"));
    }

    @Test
    void testLogin_When_DisableInternalUserManagement_Is_True() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, true);
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeExists("prompts"))
                .andExpect(content().string(not(containsString("/create_account"))));
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, false);
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = "assetBaseUrl=//cdn.example.com/resources")
    class DefaultLogo {
        @Test
        void testDefaultLogo(@Autowired MockMvc mockMvc) throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(content().string(containsString("url(//cdn.example.com/resources/images/product-logo.png)")));
        }
    }

    @Test
    void testCustomLogo() throws Exception {
        setZoneFavIconAndProductLogo(webApplicationContext, identityZoneConfiguration, null, "/bASe/64+");

        mockMvc.perform(get("/login"))
                .andExpect(content().string(allOf(containsString("url(data:image/png;base64,/bASe/64+)"), not(containsString("url(/uaa/resources/oss/images/product-logo.png)")))));
    }

    @Test
    void testCustomFavIcon() throws Exception {
        setZoneFavIconAndProductLogo(webApplicationContext, identityZoneConfiguration, "/sM4lL==", null);

        mockMvc.perform(get("/login"))
                .andExpect(content().string(allOf(containsString("<link href='data:image/png;base64,/sM4lL==' rel='shortcut icon' />"), not(containsString("square-logo.png")))));
    }

    @Test
    void testCustomFavIcon_With_LineBreaks() throws Exception {
        setZoneFavIconAndProductLogo(webApplicationContext, identityZoneConfiguration, "/sM4\n\nlL==", "/sM4\n\nlL==");

        mockMvc.perform(get("/login"))
                .andExpect(content().string(allOf(containsString("<link href='data:image/png;base64,/sM4\n\nlL==' rel='shortcut icon' />"), not(containsString("square-logo.png")))))
                .andExpect(content().string(allOf(containsString("<style>.header-image {background-image: url(data:image/png;base64,/sM4lL==);}</style>"), not(containsString("product-logo.png")))));
    }

    @Test
    void testDefaultFooter() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(content().string(containsString(cfCopyrightText)))
                .andExpect(content().string(not(containsString(CF_LAST_LOGIN))));
    }

    @Test
    void testCustomizedFooter() throws Exception {
        String customFooterText = "This text should be in the footer.";
        BrandingInformation branding = new BrandingInformation();
        branding.setFooterLegalText(customFooterText);
        identityZoneConfiguration.setBranding(branding);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), identityZoneConfiguration);

        mockMvc.perform(get("/login"))
                .andExpect(content().string(allOf(containsString(customFooterText), not(containsString(cfCopyrightText)))))
                .andExpect(content().string(not(containsString(CF_LAST_LOGIN))));
    }

    @Test
    void testCustomCompanyName() throws Exception {
        String companyName = "Big Company";
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        identityZoneConfiguration.setBranding(branding);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), identityZoneConfiguration);

        String expectedFooterText = String.format(defaultCopyrightTemplate, companyName);
        mockMvc.perform(get("/login"))
                .andExpect(content().string(allOf(containsString(expectedFooterText))));
    }

    @Test
    void testCustomCompanyNameInZone(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        String companyName = "Big Company";
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        identityZoneConfiguration.setBranding(branding);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), identityZoneConfiguration);

        branding = new BrandingInformation();
        String zoneCompanyName = "Zone Company";
        branding.setCompanyName(zoneCompanyName);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);

        IdentityZone identityZone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        String expectedFooterText = String.format(defaultCopyrightTemplate, zoneCompanyName);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(content().string(allOf(containsString(expectedFooterText))));
    }

    @Test
    void testFooterLinks() throws Exception {
        Map<String, String> footerLinks = new HashMap<>();
        footerLinks.put("Terms of Use", "/terms.html");
        footerLinks.put("Privacy", "/privacy");
        // Insanity
        BrandingInformation branding = new BrandingInformation();
        branding.setFooterLinks(footerLinks);
        identityZoneConfiguration.setBranding(branding);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), identityZoneConfiguration);

        mockMvc.perform(get("/login")).andExpect(content().string(containsString("<a href=\"/privacy\">Privacy</a> &mdash; <a href=\"/terms.html\">Terms of Use</a>")));
    }

    @Test
    void testForgotPasswordPageDoesNotHaveCsrf() throws Exception {
        mockMvc.perform(get("/forgot_password"))
                .andExpect(status().isOk())
                .andExpect(view().name("forgot_password"))
                .andExpect(content().string(containsString("action=\"/forgot_password.do\"")))
                .andExpect(content().string(not(containsString("name=\"X-Uaa-Csrf\""))));
    }

    @Test
    void testForgotPasswordSubmitDoesNotValidateCsrf() throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        mockMvc.perform(
                post("/forgot_password.do")
                        .param("username", "marissa")
                        .with(cookieCsrf().useInvalidToken()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("email_sent?code=reset_password"));
    }

    @Test
    void testChangePasswordPageDoesHaveCsrf() throws Exception {
        mockMvc.perform(
                get("/change_password")
                        .with(securityContext(MockMvcUtils.getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId())))
        )
                .andExpect(status().isOk())
                .andExpect(view().name("change_password"))
                .andExpect(content().string(containsString("action=\"/change_password.do\"")))
                .andExpect(content().string(containsString("name=\"X-Uaa-Csrf\"")));
    }

    @Test
    void testChangePasswordSubmitDoesValidateCsrf(
            @Autowired ScimUserProvisioning scimUserProvisioning
    ) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        ScimUser user = createUser(scimUserProvisioning, generator, IdentityZone.getUaaZoneId());
        mockMvc.perform(
                post("/change_password.do")
                        .with(securityContext(MockMvcUtils.getUaaSecurityContext(user.getUserName(), webApplicationContext, IdentityZoneHolder.getCurrentZoneId())))
                        .param("current_password", user.getPassword())
                        .param("new_password", "newSecr3t")
                        .param("confirm_password", "newSecr3t")
                        .with(cookieCsrf().useInvalidToken()))
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));

        mockMvc.perform(
                post("/change_password.do")
                        .with(securityContext(MockMvcUtils.getUaaSecurityContext(user.getUserName(), webApplicationContext, IdentityZoneHolder.getCurrentZoneId())))
                        .param("current_password", user.getPassword())
                        .param("new_password", "newSecr3t")
                        .param("confirm_password", "newSecr3t")
                        .with(cookieCsrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"));
    }

    @Test
    void testLogOut() throws Exception {
        mockMvc.perform(get("/uaa/logout.do").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/login"))
                .andExpect(emptyCurrentUserCookie());
    }

    @Test
    void testLogOutIgnoreRedirectParameter() throws Exception {
        mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/login"))
                .andExpect(emptyCurrentUserCookie());
    }

    @Test
    void testLogOutEnableRedirectParameter() throws Exception {
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(singletonList("https://www.google.com"));
        MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("https://www.google.com"))
                    .andExpect(emptyCurrentUserCookie());
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLogOutAllowInternalRedirect() throws Exception {
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "http://localhost/uaa/internal-location").contextPath("/uaa"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://localhost/uaa/internal-location"))
                    .andExpect(emptyCurrentUserCookie());
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLogOutWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(singletonList("https://www.google.com"));
        MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("https://www.google.com"))
                    .andExpect(emptyCurrentUserCookie());
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLogOutNotWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(singletonList("https://www.yahoo.com"));
        MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/uaa/login"))
                    .andExpect(emptyCurrentUserCookie());
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLogOutNullWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(singletonList("http*://www.google.com"));
        MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("https://www.google.com"))
                    .andExpect(emptyCurrentUserCookie());
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLogOutEmptyWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(EMPTY_LIST);
        MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/uaa/login"))
                    .andExpect(emptyCurrentUserCookie());
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLogoutRedirectIsEnabledInZone(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) {
        String zoneId = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        zone.setConfig(new IdentityZoneConfiguration());
        zone = identityZoneProvisioning.create(zone);
        assertFalse(zone.getConfig().getLinks().getLogout().isDisableRedirectParameter());
    }

    @Test
    void testLogOutChangeUrlValue() throws Exception {
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        assertFalse(original.isDisableRedirectParameter());
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        logout.setRedirectUrl("https://www.google.com");
        MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").contextPath("/uaa"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("https://www.google.com"))
                    .andExpect(emptyCurrentUserCookie());
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLogOutWithClientRedirect() throws Exception {
        Links.Logout original = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        Links.Logout logout = MockMvcUtils.getLogout(webApplicationContext, IdentityZone.getUaaZoneId());
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(EMPTY_LIST);
        MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), logout);
        try {
            String clientId = generator.generate();
            BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
            client.setClientSecret(clientId);
            MockMvcUtils.createClient(webApplicationContext, client, getUaa());
            mockMvc.perform(
                    get("/uaa/logout.do")
                            .param(CLIENT_ID, clientId)
                            .param("redirect", "http://testing.com")
                            .contextPath("/uaa")
            )
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://testing.com"))
                    .andExpect(emptyCurrentUserCookie());

            mockMvc.perform(
                    get("/uaa/logout.do")
                            .param(CLIENT_ID, clientId)
                            .param("redirect", "http://www.wildcard.testing")
                            .contextPath("/uaa")
            )
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://www.wildcard.testing"))
                    .andExpect(emptyCurrentUserCookie());

            mockMvc.perform(
                    get("/uaa/logout.do")
                            .param(CLIENT_ID, "non-existent-client")
                            .param("redirect", "http://www.wildcard.testing")
                            .contextPath("/uaa")
            )
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/uaa/login"))
                    .andExpect(emptyCurrentUserCookie());
        } finally {
            MockMvcUtils.setLogout(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLogOut_Config_For_Zone(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        String zoneId = new RandomValueStringGenerator().generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        zone.setName(zoneId);
        zone.setConfig(new IdentityZoneConfiguration());
        zone.getConfig().getLinks().getLogout()
                .setRedirectUrl("http://test.redirect.com")
                .setDisableRedirectParameter(true)
                .setRedirectParameterName("redirect");
        zone = identityZoneProvisioning.create(zone);

        //default zone
        mockMvc.perform(get("/uaa/logout.do").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/login"))
                .andExpect(emptyCurrentUserCookie());

        //other zone
        mockMvc.perform(get("/uaa/logout.do")
                .contextPath("/uaa")
                .header("Host", zoneId + ".localhost"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test.redirect.com"))
                .andExpect(emptyCurrentUserCookie());

        mockMvc.perform(get("/uaa/logout.do")
                .contextPath("/uaa")
                .header("Host", zoneId + ".localhost")
                .param("redirect", "http://google.com")
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test.redirect.com"))
                .andExpect(emptyCurrentUserCookie());

        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone = identityZoneProvisioning.update(zone);

        mockMvc.perform(get("/uaa/logout.do")
                .contextPath("/uaa")
                .header("Host", zoneId + ".localhost")
                .param("redirect", "http://google.com")
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test.redirect.com"))
                .andExpect(emptyCurrentUserCookie());

        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone.getConfig().getLinks().getLogout().setWhitelist(singletonList("http://google.com"));
        zone = identityZoneProvisioning.update(zone);

        mockMvc.perform(get("/uaa/logout.do")
                .contextPath("/uaa")
                .header("Host", zoneId + ".localhost")
                .param("redirect", "http://google.com")
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://google.com"))
                .andExpect(emptyCurrentUserCookie());

        zone.getConfig().getLinks().getLogout().setWhitelist(singletonList("http://yahoo.com"));
        identityZoneProvisioning.update(zone);

        mockMvc.perform(get("/uaa/logout.do")
                .contextPath("/uaa")
                .header("Host", zoneId + ".localhost")
                .param("redirect", "http://google.com")
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://test.redirect.com"))
                .andExpect(emptyCurrentUserCookie());

        mockMvc.perform(get("/uaa/logout.do")
                .contextPath("/uaa")
                .header("Host", zoneId + ".localhost")
                .param("redirect", "http://yahoo.com")
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://yahoo.com"))
                .andExpect(emptyCurrentUserCookie());
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = {"analytics.code=secret_code", "analytics.domain=example.com"})
    class LoginWithAnalytics {
        @Test
        void testLoginWithAnalytics(@Autowired MockMvc mockMvc) throws Exception {
            mockMvc.perform(get("/login").accept(TEXT_HTML))
                    .andExpect(status().isOk())
                    .andExpect(xpath("//body/script[contains(text(),'example.com')]").exists());
        }
    }

    @Test
    void testDefaultBranding() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("/resources/oss/images/square-logo.png"))
                .andExpect(xpath("//head/link[@href='/resources/oss/stylesheets/application.css']").exists())
                .andExpect(xpath("//head/style[text()[contains(.,'/resources/oss/images/product-logo.png')]]").exists());
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = {"assetBaseUrl=//cdn.example.com/pivotal"})
    class Branding {
        @Test
        void testExternalizedBranding(@Autowired MockMvc mockMvc) throws Exception {
            mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                    .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("//cdn.example.com/pivotal/images/square-logo.png"))
                    .andExpect(xpath("//head/link[@href='//cdn.example.com/pivotal/stylesheets/application.css']").exists())
                    .andExpect(xpath("//head/style[text()[contains(.,'//cdn.example.com/pivotal/images/product-logo.png')]]").exists());
        }
    }

    @Test
    void testAccessConfirmationPage(
            @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning
    ) throws Exception {
        ScimUser marissa = jdbcScimUserProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"", IdentityZoneHolder.get().getId()).get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());

        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal, singletonList(UaaAuthority.fromAuthorities("uaa.user")), null);
        MockHttpSession session = new MockHttpSession();
        SecurityContext securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(principal);
        session.putValue("SPRING_SECURITY_CONTEXT", securityContext);
        MockHttpServletRequestBuilder get = get("/oauth/authorize")
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

    @Test
    void testSignupsAndResetPasswordEnabled() throws Exception {
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), true);

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                .andExpect(xpath("//a[text()='Create account']").exists())
                .andExpect(xpath("//a[text()='Reset password']").exists());
    }

    @Test
    void testSignupsAndResetPasswordDisabledWithNoLinksConfigured() throws Exception {
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), false);

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                .andExpect(xpath("//a[text()='Create account']").doesNotExist())
                .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    void testSignupsAndResetPasswordDisabledWithSomeLinksConfigured() throws Exception {
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://example.com/signup");
        identityZoneConfiguration.getLinks().getSelfService().setPasswd("http://example.com/reset_passwd");
        identityZoneConfiguration.getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), identityZoneConfiguration);
        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                .andExpect(xpath("//a[text()='Create account']").doesNotExist())
                .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    void testSignupsAndResetPasswordEnabledWithCustomLinks() throws Exception {
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://example.com/signup");
        identityZoneConfiguration.getLinks().getSelfService().setPasswd("http://example.com/reset_passwd");
        identityZoneConfiguration.getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), identityZoneConfiguration);
        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                .andExpect(xpath("//a[text()='Create account']/@href").string("http://example.com/signup"))
                .andExpect(xpath("//a[text()='Reset password']/@href").string("http://example.com/reset_passwd"));
    }

    @Test
    void testLoginWithExplicitPrompts() throws Exception {
        List<Prompt> original = MockMvcUtils.getPrompts(webApplicationContext, IdentityZone.getUaaZoneId());
        try {
            Prompt first = new Prompt("how", "text", "How did I get here?");
            Prompt second = new Prompt("where", "password", "Where does that highway go to?");
            MockMvcUtils.setPrompts(webApplicationContext, IdentityZone.getUaaZoneId(), asList(first, second));

            mockMvc.perform(get("/login").accept(TEXT_HTML))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"))
                    .andExpect(model().attribute("prompts", hasKey("how")))
                    .andExpect(model().attribute("prompts", hasKey("where")))
                    .andExpect(model().attribute("prompts", not(hasKey("password"))));
        } finally {
            MockMvcUtils.setPrompts(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLoginWithExplicitJsonPrompts() throws Exception {
        List<Prompt> original = MockMvcUtils.getPrompts(webApplicationContext, IdentityZone.getUaaZoneId());
        try {
            Prompt first = new Prompt("how", "text", "How did I get here?");
            Prompt second = new Prompt("where", "password", "Where does that highway go to?");
            MockMvcUtils.setPrompts(webApplicationContext, IdentityZone.getUaaZoneId(), asList(first, second));

            mockMvc.perform(get("/login")
                    .accept(APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"))
                    .andExpect(model().attribute("prompts", hasKey("how")))
                    .andExpect(model().attribute("prompts", hasKey("where")))
                    .andExpect(model().attribute("prompts", not(hasKey("password"))));
        } finally {
            MockMvcUtils.setPrompts(webApplicationContext, IdentityZone.getUaaZoneId(), original);
        }
    }

    @Test
    void testLoginWithRemoteUaaPrompts() throws Exception {
        mockMvc.perform(get("/login")
                .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", not(hasKey("passcode"))))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    void testLoginWithRemoteUaaJsonPrompts() throws Exception {
        mockMvc.perform(get("/login")
                .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    void testDefaultMfaPrompt() throws Exception {
        IdentityZone zone = createZoneLinksZone();
        zone.getConfig().getMfaConfig().setEnabled(true);
        MockMvcUtils.updateIdentityZone(zone, webApplicationContext);

        mockMvc.perform(
                get("/login")
                        .accept(APPLICATION_JSON)
                        .header("Host", zone.getSubdomain() + ".localhost")
        )
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("mfaCode")))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", hasKey("password")));

        mockMvc.perform(
                get("/login") //default zone
                        .accept(APPLICATION_JSON)
        )
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", not(hasKey("mfaCode"))))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    void testInfoWithRemoteUaaJsonPrompts() throws Exception {
        mockMvc.perform(get("/info")
                .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    void testDefaultAndCustomSignupLink() throws Exception {
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "/create_account")));
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://www.example.com/signup");
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), identityZoneConfiguration);
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "http://www.example.com/signup")));
    }

    @Test
    void testLocalSignupDisabled() throws Exception {
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), false);
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @Test
    void testCustomSignupLinkWithLocalSignupDisabled() throws Exception {
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), false);
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @Test
    void testSamlLoginLinksShowActiveProviders(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String activeAlias = "login-saml-" + generator.generate();
        String inactiveAlias = "login-saml-" + generator.generate();

        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(activeAlias)
                .setLinkText("Active SAML Provider")
                .setShowSamlLink(true)
                .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
        activeIdentityProvider.setType(SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setOriginKey(activeAlias);
        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider);

        metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition inactiveSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(inactiveAlias)
                .setLinkText("You should not see me")
                .setZoneId(identityZone.getId());
        IdentityProvider inactiveIdentityProvider = new IdentityProvider();
        inactiveIdentityProvider.setType(SAML);
        inactiveIdentityProvider.setName("Inactive SAML Provider");
        inactiveIdentityProvider.setConfig(inactiveSamlIdentityProviderDefinition);
        inactiveIdentityProvider.setActive(false);
        inactiveIdentityProvider.setOriginKey(inactiveAlias);
        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, inactiveIdentityProvider);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[text()='" + activeSamlIdentityProviderDefinition.getLinkText() + "']").exists())
                .andExpect(xpath("//a[text()='" + inactiveSamlIdentityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @Test
    void testSamlRedirectWhenTheOnlyProvider(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String alias = "login-saml-" + generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("Active SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
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
        SessionUtils.setSavedRequestSession(session, savedRequest);

        mockMvc.perform(get("/login")
                .accept(TEXT_HTML)
                .session(session)
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/saml/discovery?returnIDParam=idp&entityID=" + identityZone.getSubdomain() + ".cloudfoundry-saml-login&idp=" + alias + "&isPassive=true"));

        mockMvc.perform(get("/login")
                .accept(APPLICATION_JSON)
                .session(session)
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());

        IdentityProvider uaaProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        try {
            IdentityZoneHolder.set(identityZone);
            uaaProvider.setActive(false);
            jdbcIdentityProviderProvisioning.update(uaaProvider, uaaProvider.getIdentityZoneId());
            mockMvc.perform(get("/login")
                    .accept(APPLICATION_JSON)
                    .session(session)
                    .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                    .andExpect(status().isOk());
        } finally {
            IdentityZoneHolder.set(identityZone);
            uaaProvider.setActive(true);
            jdbcIdentityProviderProvisioning.update(uaaProvider, uaaProvider.getIdentityZoneId());
            IdentityZoneHolder.clear();
        }
    }

    @Test
    void samlRedirect_onlyOneProvider_noClientContext(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String alias = "login-saml-" + generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("Active SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
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

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/saml/discovery?returnIDParam=idp&entityID=" + identityZone.getSubdomain() + ".cloudfoundry-saml-login&idp=" + alias + "&isPassive=true"));
        IdentityZoneHolder.clear();
    }

    @Test
    void externalOauthRedirect_onlyOneProvider_noClientContext_and_ResponseType_Set(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String oauthAlias = createOIDCProviderInZone(jdbcIdentityProviderProvisioning, identityZone, null);

        IdentityZoneHolder.set(identityZone);
        IdentityProvider uaaIdentityProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        MvcResult mvcResult = mockMvc.perform(get("/login").accept(TEXT_HTML)
                .servletPath("/login")
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location, startsWith("http://auth.url"));
        assertThat(queryParams, hasEntry("client_id", "uaa"));
        assertThat(queryParams, hasEntry("response_type", "code+id_token"));
        assertThat(queryParams, hasEntry("redirect_uri", "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias));
        assertThat(queryParams, hasEntry("scope", "openid+roles"));
        assertThat(queryParams, hasKey("nonce"));

        IdentityZoneHolder.clear();
    }

    @Test
    void ExternalOAuthRedirectOnlyOneProviderWithDiscoveryUrl(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        final String zoneAdminClientId = "admin";
        final String oidcMetaEndpoint = "http://mocked/.well-known/openid-configuration";
        final String oidcAuthUrl = "http://againmocked/oauth/auth";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String oauthAlias = createOIDCProviderInZone(jdbcIdentityProviderProvisioning, identityZone, oidcMetaEndpoint);
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setAuthUrl(new URL(oidcAuthUrl));
            return null;
        }).when(oidcMetadataFetcher)
            .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        IdentityZoneHolder.set(identityZone);
        IdentityProvider uaaIdentityProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        MvcResult mvcResult = mockMvc.perform(get("/login").accept(TEXT_HTML)
                .servletPath("/login")
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location, startsWith(oidcAuthUrl));
        assertThat(queryParams, hasEntry("client_id", "uaa"));
        assertThat(queryParams, hasEntry("response_type", "code+id_token"));
        assertThat(queryParams, hasEntry("redirect_uri", "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias));
        assertThat(queryParams, hasEntry("scope", "openid+roles"));
        assertThat(queryParams, hasKey("nonce"));

        IdentityZoneHolder.clear();
    }

    @Test
    void oauthRedirect_stateParameterPassedGetsReturned(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String oauthAlias = createOIDCProviderInZone(jdbcIdentityProviderProvisioning, identityZone, null);

        IdentityZoneHolder.set(identityZone);
        IdentityProvider uaaIdentityProvider = jdbcIdentityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        MvcResult mvcResult = mockMvc.perform(get("/login").accept(TEXT_HTML)
                .servletPath("/login")
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location, startsWith("http://auth.url"));
        assertThat(queryParams, hasEntry("client_id", "uaa"));
        assertThat(queryParams, hasEntry("response_type", "code+id_token"));
        assertThat(queryParams, hasEntry("redirect_uri", "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias));
        assertThat(queryParams, hasEntry("scope", "openid+roles"));
        assertThat(queryParams, hasKey("nonce"));
        assertThat(queryParams, hasEntry(is("state"), not(isEmptyOrNullString())));

        IdentityZoneHolder.clear();
    }

    @Test
    void testLoginHintRedirect(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        MockMvcUtils.IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();

        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));
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
        SessionUtils.setSavedRequestSession(session, savedRequest);


        MvcResult mvcResult = mockMvc.perform(get("/login")
                .accept(TEXT_HTML)
                .session(session)
                .servletPath("/login")
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
        )
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location, startsWith("http://auth.url"));
        assertThat(queryParams, hasEntry("client_id", "uaa"));
        assertThat(queryParams, hasEntry("response_type", "code"));
        assertThat(queryParams, hasEntry("redirect_uri", "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias));
        assertThat(queryParams, hasEntry("scope", "openid+roles"));
        assertThat(queryParams, hasKey("nonce"));

        IdentityZoneHolder.clear();
    }

    @Test
    void noRedirect_ifProvidersOfDifferentTypesPresent(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String alias = "login-saml-" + generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("Active SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
        activeIdentityProvider.setType(SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setOriginKey(alias);
        createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider);

        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();

        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));
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

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
        IdentityZoneHolder.clear();
    }

    @Test
    void testNoCreateAccountLinksWhenUAAisNotAllowedProvider(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String alias2 = "login-saml-" + generator.generate();
        String alias3 = "login-saml-" + generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write", "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition3 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, "http://example3.com/saml/metadata"))
                .setIdpEntityAlias(alias3)
                .setLinkText("Active3 SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider3 = new IdentityProvider();
        activeIdentityProvider3.setType(SAML);
        activeIdentityProvider3.setName("Active 3 SAML Provider");
        activeIdentityProvider3.setActive(true);
        activeIdentityProvider3.setConfig(activeSamlIdentityProviderDefinition3);
        activeIdentityProvider3.setOriginKey(alias3);
        activeIdentityProvider3 = createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, activeIdentityProvider3);

        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition2 = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, "http://example2.com/saml/metadata"))
                .setIdpEntityAlias(alias2)
                .setLinkText("Active2 SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider2 = new IdentityProvider();
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
        SessionUtils.setSavedRequestSession(session, savedRequest);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
                .session(session)
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[text()='Create account']").doesNotExist())
                .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    void testDeactivatedProviderIsRemovedFromSamlLoginLinks(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        String alias = "login-saml-" + generator.generate();
        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("SAML Provider")
                .setShowSamlLink(true)
                .setZoneId(identityZone.getId());
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(SAML);
        identityProvider.setName("SAML Provider");
        identityProvider.setActive(true);
        identityProvider.setConfig(samlIdentityProviderDefinition);
        identityProvider.setOriginKey(alias);

        identityProvider = createIdentityProvider(jdbcIdentityProviderProvisioning, identityZone, identityProvider);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']").exists());

        identityProvider.setActive(false);
        jdbcIdentityProviderProvisioning.update(identityProvider, identityZone.getId());

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @Test
    void testChangeEmailWithoutAuthenticationReturnsRedirect() throws Exception {
        mockMvc.perform(get("/change_email").accept(TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    void testChangeEmailPageHasCsrf() throws Exception {
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        MockHttpServletRequestBuilder get = get("/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));
        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")));
    }

    @Test
    void testChangeEmailSubmitWithMissingCsrf() throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        MockHttpServletRequestBuilder get = get("/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));
        MockHttpSession session = (MockHttpSession) mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")))
                .andReturn().getRequest().getSession();

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
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

    @Test
    void testChangeEmailSubmitWithInvalidCsrf() throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        MockHttpServletRequestBuilder get = get("/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));
        MockHttpSession session = (MockHttpSession) mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")))
                .andReturn().getRequest().getSession();

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
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

    @Test
    void testChangeEmailSubmitWithSpringSecurityForcedCsrf() throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());
        //example shows to to test a request that is secured by csrf and you wish to bypass it
        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
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

    @Test
    void testChangeEmailSubmitWithCorrectCsrf() throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        MockHttpServletRequestBuilder get = get("/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));

        MvcResult result = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")))
                .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession();

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
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

    @Test
    void testChangeEmailDoNotLoggedIn() throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
                .accept(TEXT_HTML)
                .with(cookieCsrf());
        mockMvc.perform(changeEmail)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));

        changeEmail = post("/change_email.do")
                .accept(TEXT_HTML)
                .with(cookieCsrf());
        mockMvc.perform(changeEmail)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));

        changeEmail = post("/change_email.do")
                .accept(TEXT_HTML)
                .with(cookieCsrf().useInvalidToken())
                .with(securityContext(marissaContext));
        mockMvc.perform(changeEmail)
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));
    }

    @Test
    void testChangeEmailNoCsrfReturns403AndInvalidRequest() throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        MockHttpServletRequestBuilder get = get("/change_email")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext));

        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("X-Uaa-Csrf")))
                .andReturn();

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
                .accept(TEXT_HTML)
                .with(securityContext(marissaContext))
                .with(cookieCsrf().useInvalidToken())
                .param("newEmail", "test@test.org")
                .param("client_id", "");
        mockMvc.perform(changeEmail)
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));
    }

    @Test
    void testCsrfForInvitationAcceptPost(@Autowired ExpiringCodeStore expiringCodeStore) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext, IdentityZoneHolder.getCurrentZoneId());
        AnonymousAuthenticationToken inviteToken = new AnonymousAuthenticationToken("invited-test", marissaContext.getAuthentication().getPrincipal(), singletonList(UaaAuthority.UAA_INVITED));
        MockHttpSession inviteSession = new MockHttpSession();
        SecurityContext inviteContext = new SecurityContextImpl();
        inviteContext.setAuthentication(inviteToken);
        inviteSession.setAttribute("SPRING_SECURITY_CONTEXT", inviteContext);

        Map<String, String> codeData = new HashMap();
        codeData.put("user_id", ((UaaPrincipal) marissaContext.getAuthentication().getPrincipal()).getId());
        codeData.put("email", ((UaaPrincipal) marissaContext.getAuthentication().getPrincipal()).getEmail());
        codeData.put("origin", UAA);

        ExpiringCode code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + 1000 * 60), null, IdentityZoneHolder.get().getId());

        //logged in with valid CSRF
        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
                .session(inviteSession)
                .with(cookieCsrf())
                .param("code", code.getCode())
                .param("client_id", "random")
                .param("password", "password")
                .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern("accept?error_message_code=form_error&code=*"))
        ;

        //logged in, invalid CSRF
        post = post("/invitations/accept.do")
                .session(inviteSession)
                .with(cookieCsrf().useInvalidToken())
                .param("client_id", "random")
                .param("password", "password")
                .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
                .andExpect(status().isForbidden())
                .andExpect(forwardedUrl("/invalid_request"));

        //not logged in, no CSRF
        post = post("/invitations/accept.do")
                .param("client_id", "random")
                .param("password", "password")
                .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login?error=invalid_login_request"));


        //not logged in, valid CSRF(can't happen)
        post = post("/invitations/accept.do")
                .with(cookieCsrf())
                .param("client_id", "random")
                .param("password", "password")
                .param("code", "notvalidated")
                .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));

    }

    /**
     * Positive test case that exercises the CORS logic for dealing with the "X-Requested-With" header.
     *
     * @throws Exception
     */
    @Test
    void testLogOutCorsPreflight(@Autowired CorsFilter corsFilter) throws Exception {
        corsFilter.setCorsXhrAllowedOrigins(asList("^localhost$", "^*\\.localhost$"));
        corsFilter.setCorsXhrAllowedUris(singletonList("^/logout\\.do$"));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "localhost");
        mockMvc.perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    /**
     * Positive test case that exercises the CORS logic for dealing with the "X-Requested-With" header.
     *
     * @throws Exception
     */
    @Test
    void testLogOutCorsPreflightForIdentityZone(@Autowired CorsFilter corsFilter) throws Exception {
        corsFilter.setCorsXhrAllowedOrigins(asList("^localhost$", "^*\\.localhost$"));
        corsFilter.setCorsXhrAllowedUris(singletonList("^/logout.do$"));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "testzone1.localhost");
        mockMvc.perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    /**
     * This should avoid the logic for X-Requested-With header entirely.
     *
     * @throws Exception on test failure
     */
    @Test
    void testLogOutCorsPreflightWithStandardHeader(@Autowired CorsFilter corsFilter) throws Exception {
        corsFilter.setCorsXhrAllowedOrigins(singletonList("^localhost$"));
        corsFilter.setCorsXhrAllowedUris(singletonList("^/logout\\.do$"));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "Accept");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "localhost");
        mockMvc.perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    /**
     * The endpoint is not white-listed to allow CORS requests with the "X-Requested-With" header so the
     * CorsFilter returns a 403.
     *
     * @throws Exception on test failure
     */
    @Test
    void testLogOutCorsPreflightWithUnallowedEndpoint(@Autowired CorsFilter corsFilter) throws Exception {
        corsFilter.setCorsXhrAllowedOrigins(singletonList("^localhost$"));
        corsFilter.setCorsXhrAllowedUris(singletonList("^/logout\\.do$"));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "localhost");
        mockMvc.perform(options("/logout.dont").headers(httpHeaders)).andExpect(status().isForbidden());
    }

    /**
     * The access control request method is not a GET therefore CORS requests with the "X-Requested-With"
     * header are not allowed and the CorsFilter returns a 405.
     *
     * @throws Exception on test failure
     */
    @Test
    void testLogOutCorsPreflightWithUnallowedMethod(@Autowired CorsFilter corsFilter) throws Exception {
        corsFilter.setCorsXhrAllowedOrigins(singletonList("^localhost$"));
        corsFilter.setCorsXhrAllowedUris(singletonList("^/logout\\.do$"));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "POST");
        httpHeaders.add("Origin", "localhost");
        mockMvc.perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isMethodNotAllowed());
    }

    /**
     * The request origin is not white-listed to allow CORS requests with the "X-Requested-With" header so the
     * CorsFilter returns a 403.
     *
     * @throws Exception on test failure
     */
    @Test
    void testLogOutCorsPreflightWithUnallowedOrigin(@Autowired CorsFilter corsFilter) throws Exception {
        corsFilter.setCorsXhrAllowedOrigins(singletonList("^localhost$"));
        corsFilter.setCorsXhrAllowedUris(singletonList("^/logout\\.do$"));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "fuzzybunnies.com");
        mockMvc.perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isForbidden());
    }

    @Test
    void login_LockoutPolicySucceeds_ForDefaultZone(
            @Autowired ScimUserProvisioning scimUserProvisioning
    ) throws Exception {
        ScimUser userToLockout = createUser(scimUserProvisioning, generator, IdentityZone.getUaaZoneId());
        attemptUnsuccessfulLogin(mockMvc, 5, userToLockout.getUserName(), "");
        mockMvc.perform(post("/uaa/login.do")
                .contextPath("/uaa")
                .with(cookieCsrf())
                .param("username", userToLockout.getUserName())
                .param("password", userToLockout.getPassword()))
                .andExpect(redirectedUrl("/uaa/login?error=account_locked"))
                .andExpect(emptyCurrentUserCookie());
    }

    @Test
    void login_LockoutPolicySucceeds_WhenPolicyIsUpdatedByApi(
            @Autowired ScimUserProvisioning scimUserProvisioning,
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        changeLockoutPolicyForIdpInZone(jdbcIdentityProviderProvisioning, zone);

        ScimUser userToLockout = createUser(scimUserProvisioning, generator, zone.getId());

        attemptUnsuccessfulLogin(mockMvc, 2, userToLockout.getUserName(), subdomain);

        mockMvc.perform(post("/uaa/login.do")
                .contextPath("/uaa")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .with(cookieCsrf())
                .param("username", userToLockout.getUserName())
                .param("password", userToLockout.getPassword()))
                .andExpect(redirectedUrl("/uaa/login?error=account_locked"))
                .andExpect(emptyCurrentUserCookie());
    }

    @Test
    void autologin_with_validCode_RedirectsToSavedRequest_ifPresent(
            @Autowired JdbcExpiringCodeStore jdbcExpiringCodeStore
    ) throws Exception {
        MockHttpSession session = MockMvcUtils.getSavedRequestSession();

        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        jdbcExpiringCodeStore.setGenerator(generator);

        AutologinRequest request = new AutologinRequest();
        request.setUsername("marissa");
        request.setPassword("koala");
        mockMvc.perform(post("/autologin")
                .header("Authorization", "Basic " + new String(Base64.encode("admin:adminsecret".getBytes())))
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk());

        mockMvc.perform(get("/autologin")
                .session(session)
                .param("code", "test" + generator.counter.get())
                .param("client_id", "admin"))
                .andExpect(redirectedUrl("http://test/redirect/oauth/authorize"));
    }

    @Test
    void autologin_with_validCode_RedirectsToHome(
            @Autowired JdbcExpiringCodeStore jdbcExpiringCodeStore
    ) throws Exception {
        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        jdbcExpiringCodeStore.setGenerator(generator);

        AutologinRequest request = new AutologinRequest();
        request.setUsername("marissa");
        request.setPassword("koala");
        mockMvc.perform(post("/autologin")
                .header("Authorization", "Basic " + new String(Base64.encode("admin:adminsecret".getBytes())))
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk());

        mockMvc.perform(get("/autologin")
                .param("code", "test" + generator.counter.get())
                .param("client_id", "admin"))
                .andExpect(redirectedUrl("home"));
    }

    @Test
    void idpDiscoveryPageDisplayed_IfFlagIsEnabled(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        mockMvc.perform(get("/login")
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"))
                .andExpect(content().string(containsString("Sign in")))
                .andExpect(xpath("//input[@name='email']").exists())
                .andExpect(xpath("//div[@class='action']//a").string("Create account"))
                .andExpect(xpath("//input[@name='commit']/@value").string("Next"));
    }

    @Test
    void idpDiscoveryPageNotDisplayed_IfFlagIsEnabledAndDiscoveryUnsuccessfulPreviously(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        mockMvc.perform(get("/login?discoveryPerformed=true")
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/password"));
    }

    @Test
    void idpDiscoveryClientNameDisplayed_WithUTF8Characters(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        String utf8String = "\u7433\u8D3A";
        String clientName = "woohoo-" + utf8String;
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        MockHttpSession session = new MockHttpSession();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, clientName);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedRequest savedRequest = getSavedRequest(client);
        SessionUtils.setSavedRequestSession(session, savedRequest);

        mockMvc.perform(get("/login")
                .session(session)
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"))
                .andExpect(content().string(containsString("Sign in to continue to " + clientName)))
                .andExpect(xpath("//input[@name='email']").exists())
                .andExpect(xpath("//div[@class='action']//a").string("Create account"))
                .andExpect(xpath("//input[@name='commit']/@value").string("Next"));
    }

    @Test
    void accountChooserEnabled_NoSaveAccounts(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        String clientName = "woohoo";
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        MockHttpSession session = new MockHttpSession();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, clientName);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedAccountOption savedAccount = new SavedAccountOption();
        savedAccount.setEmail("test@example.org");
        savedAccount.setOrigin("uaa");
        savedAccount.setUserId("1234-5678");
        savedAccount.setUsername("test@example.org");
        mockMvc.perform(get("/login")
                .session(session)
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"));
    }

    @Test
    void accountChooserEnabled(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        String clientName = "woohoo";
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        MockHttpSession session = new MockHttpSession();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, clientName);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedAccountOption savedAccount = new SavedAccountOption();
        savedAccount.setEmail("test@example.org");
        savedAccount.setOrigin("uaa");
        savedAccount.setUserId("1234-5678");
        savedAccount.setUsername("test@example.org");
        mockMvc.perform(get("/login")
                .session(session)
                .cookie(new Cookie("Saved-Account-12345678", URLEncoder.encode(JsonUtils.writeValueAsString(savedAccount))))
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/account_chooser"));
    }

    @Test
    void accountChooserWithoutDiscovery(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(false);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(get("/login")
                .session(session)
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/origin"));
    }

    @Test
    void accountChooserWithoutDiscovery_loginWithProvidedLoginHint(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning, @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(false);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        String originKey = createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code");
        String loginHint = "%7B%22origin%22%3A%22"+originKey+"%22%7D";

        MvcResult mvcResult = mockMvc.perform(post("/origin-chooser")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .servletPath("/origin-chooser")
                .param("login_hint", originKey)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location, startsWith("/login"));
        assertThat(queryParams, hasEntry("login_hint", loginHint));
        assertThat(queryParams, hasEntry("discoveryPerformed", "true"));
    }

    @Test
    void accountChooserWithoutDiscovery_noDefaultReturnsLoginPage(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning, @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        assumeFalse(isLimitedMode(limitedModeUaaFilter), "Test only runs in non limited mode.");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(false);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code");

        MvcResult mvcResult = mockMvc.perform(post("/origin-chooser")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .servletPath("/origin-chooser")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location, startsWith("/login"));
        assertThat(queryParams, not(hasKey("login_hint")));
        assertThat(queryParams, hasEntry("discoveryPerformed", "true"));
    }

    @Test
    void emailPageIdpDiscoveryEnabled_SelfServiceLinksDisabled(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setLinks(new Links().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(false)));
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);

        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), false);

        mockMvc.perform(MockMvcRequestBuilders.get("/login")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(xpath("//div[@class='action']//a").doesNotExist());
    }

    @Test
    void idpDiscoveryRedirectsToSamlExternalProvider_withClientContext(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        String originKey = generator.generate();
        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone);

        mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .session(session)
                .param("email", "marissa@test.org")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/saml/discovery?returnIDParam=idp&entityID=" + zone.getSubdomain() + ".cloudfoundry-saml-login&idp=" + originKey + "&isPassive=true"));
    }

    @Test
    void idpDiscoveryRedirectsToOIDCProvider(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String subdomain = "oidc-discovery-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        String originKey = createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "id_token code");

        MvcResult mvcResult = mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .servletPath("/login/idp_discovery")
                .param("email", "marissa@test.org")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location, startsWith("http://myauthurl.com"));
        assertThat(queryParams, hasEntry("client_id", "id"));
        assertThat(queryParams, hasEntry("response_type", "id_token+code"));
        assertThat(queryParams, hasEntry("redirect_uri", "http%3A%2F%2F" + subdomain + ".localhost%2Flogin%2Fcallback%2F" + originKey));
        assertThat(queryParams, hasKey("nonce"));
    }

    @Test
    void multiple_oidc_providers_use_response_type_in_url(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String subdomain = "oidc-idp-discovery-multi-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, null);
        createOIDCProvider(jdbcIdentityProviderProvisioning, generator, zone, "code id_token");

        mockMvc.perform(get("/login")
                .header("Accept", TEXT_HTML)
                .servletPath("/login")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("http://myauthurl.com?client_id=id&amp;response_type=code&")))
                .andExpect(content().string(containsString("http://myauthurl.com?client_id=id&amp;response_type=code+id_token&")));
    }

    @Test
    void idpDiscoveryWithNoEmailDomainMatch_withClientContext(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        IdentityZoneHolder.set(zone);
        IdentityProvider identityProvider = jdbcIdentityProviderProvisioning.retrieveByOrigin("uaa", zone.getId());
        identityProvider.setConfig(new AbstractIdentityProviderDefinition().setEmailDomain(Collections.singletonList("totally-different.org")));
        jdbcIdentityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone);

        mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .session(session)
                .param("email", "marissa@other.domain")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?discoveryPerformed=true&email=marissa%40other.domain"));
    }

    @Test
    void idpDiscoveryWithMultipleEmailDomainMatches_withClientContext(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        IdentityZoneHolder.set(zone);
        IdentityProvider identityProvider = jdbcIdentityProviderProvisioning.retrieveByOrigin("uaa", zone.getId());
        identityProvider.setConfig(new AbstractIdentityProviderDefinition().setEmailDomain(Collections.singletonList("test.org")));
        jdbcIdentityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone);

        mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .session(session)
                .param("email", "marissa@test.org")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?discoveryPerformed=true&email=marissa%40test.org"));
    }

    @Test
    void idpDiscoveryWithUaaFallBack_withClientContext(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone);

        mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .session(session)
                .param("email", "marissa@other.domain")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?discoveryPerformed=true&email=marissa%40other.domain"));

        mockMvc.perform(get("/login?discoveryPerformed=true&email=marissa%40other.domain")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .session(session)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(model().attributeExists("zone_name"))
                .andExpect(view().name("login"));
    }

    @Test
    void idpDiscoveryWithLdap_withClientContext(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning
    ) throws Exception {
        String subdomain = "test-zone-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(LDAP, zone.getId());
        identityProvider.setType(LDAP);
        identityProvider.setConfig(new LdapIdentityProviderDefinition().setEmailDomain(Collections.singletonList("testLdap.org")));

        createIdentityProvider(jdbcIdentityProviderProvisioning, zone, identityProvider);

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(webApplicationContext, jdbcIdentityProviderProvisioning, generator, originKey, zone);

        mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .session(session)
                .param("email", "marissa@testLdap.org")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?discoveryPerformed=true&email=marissa%40testLdap.org"));
    }

    @Test
    void passwordPageDisplayed_ifUaaIsFallbackIDPForEmailDomain(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        mockMvc.perform(post("/login/idp_discovery")
                .header("Accept", TEXT_HTML)
                .with(cookieCsrf())
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost"))
                .param("email", "marissa@koala.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?discoveryPerformed=true&email=marissa%40koala.com"));

        mockMvc.perform(get("/login?discoveryPerformed=true&email=marissa@koala.com")
                .with(cookieCsrf())
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost"))
                .header("Accept", TEXT_HTML))
                .andExpect(view().name("idp_discovery/password"))
                .andExpect(xpath("//input[@name='password']").exists())
                .andExpect(xpath("//input[@name='username']/@value").string("marissa@koala.com"))
                .andExpect(xpath("//div[@class='action pull-right']//a").string("Reset password"))
                .andExpect(xpath("//input[@type='submit']/@value").string("Sign in"));
    }

    @Test
    void passwordPageIdpDiscoveryEnabled_SelfServiceLinksDisabled() throws Exception {
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, IdentityZone.getUaaZoneId(), false);

        mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .param("email", "marissa@koala.org"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?discoveryPerformed=true&email=marissa%40koala.org"));

        mockMvc.perform(get("/login?discoveryPerformed=true&email=marissa%40koala.org")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//div[@class='action pull-right']//a").doesNotExist());
    }

    @Test
    void userNamePresentInPasswordPage(
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(webApplicationContext, mockMvc, identityZoneProvisioning, generator, config);
        mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .param("email", "test@email.com")
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?discoveryPerformed=true&email=test%40email.com"));

        mockMvc.perform(get("/login?discoveryPerformed=true&email=test@email.com")
                .with(cookieCsrf())
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(xpath("//input[@name='username']/@value").string("test@email.com"));
    }

    @Test
    void authorizeForClientWithIdpNotAllowed(
            @Autowired ScimUserProvisioning scimUserProvisioning,
            @Autowired IdentityZoneProvisioning identityZoneProvisioning
    ) throws Exception {
        String subdomain = "idp-not-allowed-" + generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone = createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone = identityZoneProvisioning.update(zone);

        ScimUser user = createUser(scimUserProvisioning, generator, zone.getId());
        MockHttpSession session = new MockHttpSession();

        SetServerNameRequestPostProcessor inZone = new SetServerNameRequestPostProcessor(subdomain + ".localhost");

        MockHttpServletRequestBuilder post = post("/uaa/login.do")
                .with(inZone)
                .with(cookieCsrf())
                .contextPath("/uaa")
                .session(session)
                .param("username", user.getUserName())
                .param("password", user.getPassword());

        mockMvc.perform(post)
                .andExpect(redirectedUrl("/uaa/"));
        // authorize for client that does not allow that idp

        String clientId = "different-provider-client";
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.setScope(singleton("uaa.user"));
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "THE APPLICATION");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, singletonList("a-different-provider"));
        HashSet<String> registeredRedirectUris = new HashSet<>();
        registeredRedirectUris.add("http://idp-not-allowed.localhost/");
        client.setRegisteredRedirectUri(registeredRedirectUris);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        MockHttpServletRequestBuilder authorize = get("/oauth/authorize")
                .with(inZone)
                .session(session)
                .param("client_id", "different-provider-client")
                .param("response_type", "code")
                .param("client_secret", "secret")
                .param("garbage", "this-should-be-preserved");

        String expectedUrl = "http://" + subdomain + ".localhost/oauth/authorize?client_id=different-provider-client&response_type=code&client_secret=secret&garbage=this-should-be-preserved";
        String html = mockMvc.perform(authorize)
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String extractPattern = "logout.do\\?redirect\\=(.*?)\">click here<";
        Pattern pattern = Pattern.compile(extractPattern);
        Matcher matcher = pattern.matcher(html);
        assertTrue(matcher.find());
        String group = matcher.group(1);
        assertEquals(expectedUrl, URLDecoder.decode(group, StandardCharsets.UTF_8));
    }

    private static MockHttpSession setUpClientAndProviderForIdpDiscovery(
            WebApplicationContext webApplicationContext,
            JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning,
            RandomValueStringGenerator generator,
            String originKey,
            IdentityZone zone) {
        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
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
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "woohoo");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, asList(originKey, "other-provider", UAA, LDAP));
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedRequest savedRequest = getSavedRequest(client);
        MockHttpSession session = new MockHttpSession();
        SessionUtils.setSavedRequestSession(session, savedRequest);
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
        @Test
        void hasValidError() throws Exception {
            mockMvc.perform(
                    get("/login?error=login_failure"))
                    .andExpect(content().string(containsString("Provided credentials are invalid. Please try again.")));
        }

        @Test
        void hasInvalidError() throws Exception {
            mockMvc.perform(
                    get("/login?error=foobar&error=login_failure"))
                    .andExpect(content().string(containsString("Error!")));
        }

        @Test
        void hasValidSuccess() throws Exception {
            mockMvc.perform(
                    get("/login?success=verify_success"))
                    .andExpect(content().string(containsString("Verification successful. Login to access your account.")));
        }

        @Test
        void hasInvalidSuccess() throws Exception {
            mockMvc.perform(
                    get("/login?success=foobar&success=verify_success"))
                    .andExpect(content().string(containsString("Success!")));
        }
    }

    private static void attemptUnsuccessfulLogin(MockMvc mockMvc, int numberOfAttempts, String username, String subdomain) throws Exception {
        String requestDomain = subdomain.equals("") ? "localhost" : subdomain + ".localhost";
        MockHttpServletRequestBuilder post = post("/uaa/login.do")
                .with(new SetServerNameRequestPostProcessor(requestDomain))
                .with(cookieCsrf())
                .contextPath("/uaa")
                .param("username", username)
                .param("password", "wrong_password");
        for (int i = 0; i < numberOfAttempts; i++) {
            mockMvc.perform(post)
                    .andExpect(redirectedUrl("/uaa/login?error=login_failure"))
                    .andExpect(emptyCurrentUserCookie());
        }
    }

    private static ResultMatcher emptyCurrentUserCookie() {
        return result -> {
            cookie().value("Current-User", isEmptyOrNullString()).match(result);
            cookie().maxAge("Current-User", 0).match(result);
            cookie().path("Current-User", "/").match(result);
        };
    }

    private static IdentityZone setupZone(
            WebApplicationContext webApplicationContext,
            MockMvc mockMvc,
            IdentityZoneProvisioning identityZoneProvisioning,
            RandomValueStringGenerator generator,
            IdentityZoneConfiguration config) throws Exception {
        String zoneId = generator.generate().toLowerCase();
        IdentityZone zone = createOtherIdentityZone(zoneId, mockMvc, webApplicationContext, false, IdentityZoneHolder.getCurrentZoneId());
        zone.setConfig(config);
        identityZoneProvisioning.update(zone);
        return zone;
    }

    private static SavedRequest getSavedRequest(BaseClientDetails client) {
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

    private static ScimUser createUser(ScimUserProvisioning scimUserProvisioning, RandomValueStringGenerator generator, String zoneId) {
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

    private static String createOIDCProvider(JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning, RandomValueStringGenerator generator, IdentityZone zone, String responseType) throws Exception {
        String originKey = generator.generate();
        AbstractExternalOAuthIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setEmailDomain(singletonList("test.org"));
        definition.setAuthUrl(new URL("http://myauthurl.com"));
        definition.setTokenKey("key");
        definition.setTokenUrl(new URL("http://mytokenurl.com"));
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
            definition.setAuthUrl(new URL("http://auth.url"));
            definition.setTokenUrl(new URL("http://token.url"));
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
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), identityZoneConfiguration);
    }

    private static final String defaultCopyrightTemplate = "Copyright " + "\u00a9" + " %s";
    private static final String cfCopyrightText = String.format(defaultCopyrightTemplate, "CloudFoundry.org Foundation, Inc.");
    private static final String CF_LAST_LOGIN = "Last Login";

    private static IdentityProvider createIdentityProvider(JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning, IdentityZone identityZone, IdentityProvider activeIdentityProvider) {
        activeIdentityProvider.setIdentityZoneId(identityZone.getId());
        return jdbcIdentityProviderProvisioning.create(activeIdentityProvider, identityZone.getId());
    }

}
