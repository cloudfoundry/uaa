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

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.home.HomeController;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.*;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderDataTests;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.sql.Timestamp;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Arrays.asList;
import static java.util.Collections.*;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.*;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.cloudfoundry.identity.uaa.zone.IdentityZone.getUaa;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
@DirtiesContext
public class LoginMockMvcTests {

    @Autowired
    private WebApplicationContext webApplicationContext;

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    private String adminToken;

    private IdentityZoneConfiguration originalConfiguration;
    private IdentityZoneConfiguration identityZoneConfiguration;
    private Links globalLinks;
    private IdentityZone identityZone;
    private MockMvc mockMvc;

    @BeforeEach
    public void setUpContext() throws Exception {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .alwaysDo(print())
                .addFilter(springSecurityFilterChain)
                .build();

        globalLinks = webApplicationContext.getBean("globalLinks", Links.class);
        SecurityContextHolder.clearContext();

        adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", null, null);
        originalConfiguration = webApplicationContext.getBean(IdentityZoneProvisioning.class).retrieve(getUaa().getId()).getConfig();
        identityZoneConfiguration = webApplicationContext.getBean(IdentityZoneProvisioning.class).retrieve(getUaa().getId()).getConfig();
        IdentityZoneHolder.setProvisioning(webApplicationContext.getBean(IdentityZoneProvisioning.class));

        bootstrapMfaProvider();
    }

    private void bootstrapMfaProvider() throws Exception {
        String subdomain = new RandomValueStringGenerator(24).generate().toLowerCase();
        identityZone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false);

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
    }

    @AfterEach
    public void resetGenerator() throws Exception {
        webApplicationContext.getBean(JdbcExpiringCodeStore.class).setGenerator(new RandomValueStringGenerator(24));
        webApplicationContext.getBean(LoginInfoEndpoint.class).setGlobalLinks(globalLinks);
        webApplicationContext.getBean(HomeController.class).setGlobalLinks(globalLinks);
    }

    @AfterEach
    public void tearDown() throws Exception {
        setSelfServiceLinksEnabled(true);
        setDisableInternalUserManagement(false);
        setZoneConfiguration(originalConfiguration);
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void access_login_page_while_logged_in() throws Exception {
        SecurityContext securityContext = MockMvcUtils.getMarissaSecurityContext(webApplicationContext);
        mockMvc.perform(
            get("/login")
                .header("Accept", MediaType.TEXT_HTML_VALUE)
                .with(securityContext(securityContext))
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"));
    }

    @Test
    public void invalid_accept_media_type() throws Exception {
        mockMvc.perform(
            get("/login")
                .header("Accept", MediaType.TEXT_XML_VALUE)
        )
            .andExpect(status().isNotAcceptable());
    }

    @Test
    public void testLogin() throws Exception {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/forgot_password")))
            .andExpect(model().attribute("links", hasEntry("createAccountLink", "/create_account")))
            .andExpect(model().attributeExists("prompts"))
            .andExpect(content().string(containsString("/create_account")));
    }

    @Test
    public void testLoginMfaRedirect() throws Exception {
        MockHttpSession session = new MockHttpSession();

        ScimUser user = createUser(identityZone.getId());

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

    public IdentityZone createZoneLinksZone() throws Exception {
        String subdomain = new RandomValueStringGenerator(24).generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false);
        zone.getConfig().getLinks().setSelfService(new Links.SelfService().setPasswd(null).setSignup(null));
        return MockMvcUtils.updateIdentityZone(zone, webApplicationContext);
    }

    @Test
    public void self_service_zone_variable_links() throws Exception {
        IdentityZone zone = createZoneLinksZone();

        mockMvc.perform(
            get("/login")
            .header("Host", zone.getSubdomain()+".localhost")
        )
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/forgot_password")))
            .andExpect(model().attribute("links", hasEntry("createAccountLink", "/create_account")))
            .andExpect(content().string(containsString("/create_account")));

        webApplicationContext.getBean(LoginInfoEndpoint.class).setGlobalLinks(
            new Links().setSelfService(
                new Links.SelfService()
                    .setPasswd("/passwd?id={zone.id}")
                    .setSignup("/signup?subdomain={zone.subdomain}")
            )
        );

        mockMvc.perform(
            get("/login")
                .header("Host", zone.getSubdomain()+".localhost")
        )
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/passwd?id="+zone.getId())))
            .andExpect(model().attribute("links", hasEntry("createAccountLink", "/signup?subdomain="+zone.getSubdomain())))
            .andExpect(content().string(containsString("/passwd?id="+zone.getId())))
            .andExpect(content().string(containsString("/signup?subdomain="+zone.getSubdomain())));

        zone.getConfig().getLinks().setSelfService(
            new Links.SelfService()
                .setPasswd("/local_passwd?id={zone.id}")
                .setSignup("/local_signup?subdomain={zone.subdomain}")
        );
        zone = MockMvcUtils.updateIdentityZone(zone, webApplicationContext);
        mockMvc.perform(
            get("/login")
                .header("Host", zone.getSubdomain()+".localhost")
        )
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/local_passwd?id="+zone.getId())))
            .andExpect(model().attribute("links", hasEntry("createAccountLink", "/local_signup?subdomain="+zone.getSubdomain())))
            .andExpect(content().string(containsString("/local_passwd?id="+zone.getId())))
            .andExpect(content().string(containsString("/local_signup?subdomain="+zone.getSubdomain())));

    }

    @Test
    public void global_zone_variable_home_redirect() throws Exception {

        IdentityZone zone = createZoneLinksZone();
        ScimUser marissa = createUser(zone.getId());

        mockMvc.perform(
            get("/")
                .with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone)))
                .header("Host", zone.getSubdomain()+".localhost")
        )
            .andDo(print())
            .andExpect(status().isOk());

        webApplicationContext.getBean(HomeController.class).setGlobalLinks(
            new Links().setHomeRedirect("http://{zone.subdomain}.redirect.to/z/{zone.id}")
        );

        mockMvc.perform(
            get("/")
                .with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone)))
                .header("Host", zone.getSubdomain()+".localhost")
        )
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("http://"+zone.getSubdomain()+".redirect.to/z/"+zone.getId()));

        zone.getConfig().getLinks().setHomeRedirect("http://configured.{zone.subdomain}.redirect.to/z/{zone.id}");
        zone = MockMvcUtils.updateIdentityZone(zone, webApplicationContext);
        mockMvc.perform(
            get("/")
                .with(securityContext(getUaaSecurityContext(marissa.getUserName(), webApplicationContext, zone)))
                .header("Host", zone.getSubdomain()+".localhost")
        )
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("http://configured."+zone.getSubdomain()+".redirect.to/z/"+zone.getId()));

    }

    @Test
    public void testLogin_Csrf_MaxAge() throws Exception {
        mockMvc
            .perform(
                get("/login"))
            .andExpect(status().isOk())
            .andExpect(cookie().maxAge(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, CookieBasedCsrfTokenRepository.DEFAULT_COOKIE_MAX_AGE));
    }

    @Test
    public void testLogin_Csrf_Reset_On_Refresh() throws Exception {
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
    public void testLoginPageReloadOnCsrfExpiry() throws Exception {
        CookieBasedCsrfTokenRepository cookieBasedCsrfTokenRepository = webApplicationContext.getBean(CookieBasedCsrfTokenRepository.class);
        cookieBasedCsrfTokenRepository.setCookieMaxAge(3);

        MvcResult mvcResult = mockMvc
                .perform(get("/login"))
                .andReturn();
        assertThat("", mvcResult.getResponse().getContentAsString(), containsString("http-equiv=\"refresh\" content=\"3\""));
        cookieBasedCsrfTokenRepository.setCookieMaxAge(CookieBasedCsrfTokenRepository.DEFAULT_COOKIE_MAX_AGE);
    }

    protected void setDisableInternalAuth(boolean disable) throws Exception {
       MockMvcUtils.setDisableInternalAuth(webApplicationContext, getUaa().getId(), disable);
    }

    protected void setDisableInternalUserManagement(boolean disabled) throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(webApplicationContext, getUaa().getId(), disabled);
    }

    protected void setSelfServiceLinksEnabled(boolean enabled) throws Exception {
        MockMvcUtils.setSelfServiceLinksEnabled(webApplicationContext, getUaa().getId(), enabled);
    }

    protected void setZoneConfiguration(IdentityZoneConfiguration configuration) throws Exception {
        MockMvcUtils.setZoneConfiguration(webApplicationContext, getUaa().getId(), configuration);
    }

    protected void setPrompts(List<Prompt> prompts) throws Exception {
        MockMvcUtils.setPrompts(webApplicationContext, getUaa().getId(), prompts);
    }

    protected List<Prompt> getPrompts() throws Exception {
        return MockMvcUtils.getPrompts(webApplicationContext, getUaa().getId());
    }

    protected Links.Logout getLogout() throws Exception {
        return MockMvcUtils.getLogout(webApplicationContext, getUaa().getId());
    }

    protected void setLogout(Links.Logout logout) throws Exception {
        MockMvcUtils.setLogout(webApplicationContext, getUaa().getId(), logout);
    }


    @Test
    public void test_cookie_csrf() throws Exception {
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

        ScimUser marissa = webApplicationContext.getBean(JdbcScimUserProvisioning.class).query("username eq 'marissa'", IdentityZoneHolder.get().getId()).get(0);

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
    public void test_case_insensitive_login() throws Exception {
        String username = "mixed-CASE-USER-"+generator.generate()+"@testdomain.com";
        ScimUser user = createUser(username, getUaa().getId());
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
    public void test_previous_login_time_upon_authentication() throws Exception {
        ScimUser user = createUser(getUaa().getId());
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
    public void testLogin_Post_When_DisableInternalUserManagement_Is_True() throws Exception {
        ScimUser user = createUser(getUaa().getId());
        setDisableInternalAuth(true);
        try {
            mockMvc.perform(post("/login.do")
                                     .with(cookieCsrf())
                                     .param("username", user.getUserName())
                                     .param("password", user.getPassword()))
                .andExpect(redirectedUrl("/login?error=login_failure"));
        } finally {
            setDisableInternalAuth(false);
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
    public void testLogin_When_DisableInternalUserManagement_Is_True() throws Exception {
        setDisableInternalUserManagement(true);
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attributeExists("prompts"))
            .andExpect(content().string(not(containsString("/create_account"))));
    }


    @Nested
    @ExtendWith(SpringExtension.class)
    @ExtendWith(HoneycombJdbcInterceptorExtension.class)
    @ExtendWith(HoneycombAuditEventTestListenerExtension.class)
    @ActiveProfiles("default")
    @WebAppConfiguration
    @ContextConfiguration(classes = TestSpringContext.class)
    @TestPropertySource(properties = "assetBaseUrl=//cdn.example.com/resources")
    class DefaultLogo {
        @Autowired
        private WebApplicationContext webApplicationContext;

        @BeforeEach
        public void setup() {
            FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
            mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                    .addFilter(springSecurityFilterChain)
                    .build();

        }

        @Test
        public void testDefaultLogo() throws Exception {
            mockMvc.perform(get("/login"))
                    .andExpect(content().string(containsString("url(//cdn.example.com/resources/images/product-logo.png)")));
        }
    }


    @Test
    public void testCustomLogo() throws Exception {
        setZoneFavIconAndProductLogo(null, "/bASe/64+");

        mockMvc.perform(get("/login"))
                .andExpect(content().string(allOf(containsString("url(data:image/png;base64,/bASe/64+)"), not(containsString("url(/uaa/resources/oss/images/product-logo.png)")))));
    }

    @Test
    public void testCustomFavIcon() throws Exception {
        setZoneFavIconAndProductLogo("/sM4lL==", null);

        mockMvc.perform(get("/login"))
            .andExpect(content().string(allOf(containsString("<link href='data:image/png;base64,/sM4lL==' rel='shortcut icon' />"), not(containsString("square-logo.png")))));
    }

    @Test
    public void testCustomFavIcon_With_LineBreaks() throws Exception {
        setZoneFavIconAndProductLogo("/sM4\n\nlL==", "/sM4\n\nlL==");

        mockMvc.perform(get("/login"))
            .andExpect(content().string(allOf(containsString("<link href='data:image/png;base64,/sM4\n\nlL==' rel='shortcut icon' />"), not(containsString("square-logo.png")))))
            .andExpect(content().string(allOf(containsString("<style>.header-image {background-image: url(data:image/png;base64,/sM4lL==);}</style>"), not(containsString("product-logo.png")))));
    }

    private void setZoneFavIconAndProductLogo(String favIcon, String productLogo) throws Exception {
        BrandingInformation branding = new BrandingInformation();
        branding.setSquareLogo(favIcon);
        branding.setProductLogo(productLogo);
        identityZoneConfiguration.setBranding(branding);
        setZoneConfiguration(identityZoneConfiguration);
    }


    private static final String defaultCopyrightTemplate =  "Copyright "+"\u00a9"+" %s";
    private static final String cfCopyrightText = String.format(defaultCopyrightTemplate, "CloudFoundry.org Foundation, Inc.");
    private static final String CF_LAST_LOGIN = "Last Login";
    @Test
    public void testDefaultFooter() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(content().string(containsString(cfCopyrightText)))
                .andExpect(content().string(not(containsString(CF_LAST_LOGIN))));
    }

    @Test
    public void testCustomizedFooter() throws Exception {
        String customFooterText = "This text should be in the footer.";
        BrandingInformation branding = new BrandingInformation();
        branding.setFooterLegalText(customFooterText);
        identityZoneConfiguration.setBranding(branding);
        setZoneConfiguration(identityZoneConfiguration);

        mockMvc.perform(get("/login"))
                .andExpect(content().string(allOf(containsString(customFooterText), not(containsString(cfCopyrightText)))))
                .andExpect(content().string(not(containsString(CF_LAST_LOGIN))));
    }

    @Test
    public void testCustomCompanyName() throws Exception {
        String companyName = "Big Company";
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        identityZoneConfiguration.setBranding(branding);
        setZoneConfiguration(identityZoneConfiguration);

        String expectedFooterText = String.format(defaultCopyrightTemplate, companyName);
        mockMvc.perform(get("/login"))
            .andExpect(content().string(allOf(containsString(expectedFooterText))));
    }

    @Test
    public void testCustomCompanyNameInZone() throws Exception {
        String companyName = "Big Company";
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        identityZoneConfiguration.setBranding(branding);
        setZoneConfiguration(identityZoneConfiguration);

        branding = new BrandingInformation();
        String zoneCompanyName = "Zone Company";
        branding.setCompanyName(zoneCompanyName);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);

        IdentityZone identityZone = setupZone(config);

        String expectedFooterText = String.format(defaultCopyrightTemplate, zoneCompanyName);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
          .andExpect(status().isOk())
          .andExpect(content().string(allOf(containsString(expectedFooterText))));
    }

    @Test
    public void testFooterLinks() throws Exception {
        Map<String, String> footerLinks = new HashMap<>();
        footerLinks.put("Terms of Use", "/terms.html");
        footerLinks.put("Privacy", "/privacy");
        // Insanity
        BrandingInformation branding = new BrandingInformation();
        branding.setFooterLinks(footerLinks);
        identityZoneConfiguration.setBranding(branding);
        setZoneConfiguration(identityZoneConfiguration);

        mockMvc.perform(get("/login")).andExpect(content().string(containsString("<a href=\"/privacy\">Privacy</a> &mdash; <a href=\"/terms.html\">Terms of Use</a>")));
    }

    @Test
    public void testForgotPasswordPageDoesNotHaveCsrf() throws Exception {
        mockMvc.perform(get("/forgot_password"))
            .andExpect(status().isOk())
            .andExpect(view().name("forgot_password"))
            .andExpect(content().string(containsString("action=\"/forgot_password.do\"")))
            .andExpect(content().string(not(containsString("name=\"X-Uaa-Csrf\""))));
    }

    @Test
    public void testForgotPasswordSubmitDoesNotValidateCsrf() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        mockMvc.perform(
            post("/forgot_password.do")
                .param("username", "marissa")
                .with(cookieCsrf().useInvalidToken()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("email_sent?code=reset_password"));
    }

    @Test
    public void testChangePasswordPageDoesHaveCsrf() throws Exception {
        mockMvc.perform(
            get("/change_password")
                .with(securityContext(MockMvcUtils.getMarissaSecurityContext(webApplicationContext)))
        )
            .andExpect(status().isOk())
            .andExpect(view().name("change_password"))
            .andExpect(content().string(containsString("action=\"/change_password.do\"")))
            .andExpect(content().string(containsString("name=\"X-Uaa-Csrf\"")));
    }

    @Test
    public void testChangePasswordSubmitDoesValidateCsrf() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        ScimUser user = createUser(getUaa().getId());
        mockMvc.perform(
            post("/change_password.do")
                .with(securityContext(MockMvcUtils.getUaaSecurityContext(user.getUserName(), webApplicationContext)))
                .param("current_password", user.getPassword())
                .param("new_password", "newSecr3t")
                .param("confirm_password", "newSecr3t")
                .with(cookieCsrf().useInvalidToken()))
            .andExpect(status().isForbidden())
            .andExpect(forwardedUrl("/invalid_request"));

        mockMvc.perform(
            post("/change_password.do")
                .with(securityContext(MockMvcUtils.getUaaSecurityContext(user.getUserName(), webApplicationContext)))
                .param("current_password", user.getPassword())
                .param("new_password", "newSecr3t")
                .param("confirm_password", "newSecr3t")
                .with(cookieCsrf()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("profile"));
    }

    private ScimUser createUser(String zoneId) throws Exception {
        String username = generator.generate()+"@testdomain.com";
        return createUser(username, zoneId);
    }
    private ScimUser createUser(String username, String zoneId) throws Exception {
        ScimUser user = new ScimUser(null, username, "Test", "User");
        user.setPrimaryEmail(username);
        user.setPassword("Secr3t");
        user = webApplicationContext.getBean(ScimUserProvisioning.class).createUser(user, user.getPassword(), zoneId);
        user.setPassword("Secr3t");
        return user;
    }

    @Test
    public void testLogOut() throws Exception {
        mockMvc.perform(get("/uaa/logout.do").contextPath("/uaa"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/uaa/login"))
            .andExpect(emptyCurrentUserCookie());
    }

    @Test
    public void testLogOutIgnoreRedirectParameter() throws Exception {
        mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/uaa/login"))
            .andExpect(emptyCurrentUserCookie());
    }

    @Test
    public void testLogOutEnableRedirectParameter() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(Arrays.asList("https://www.google.com"));
        setLogout(logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"))
                .andExpect(emptyCurrentUserCookie());
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogOutAllowInternalRedirect() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        setLogout(logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "http://localhost/uaa/internal-location").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/uaa/internal-location"))
                .andExpect(emptyCurrentUserCookie());
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogOutWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(asList("https://www.google.com"));
        setLogout(logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"))
                .andExpect(emptyCurrentUserCookie());
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogOutNotWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(asList("https://www.yahoo.com"));
        setLogout(logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/login"))
                .andExpect(emptyCurrentUserCookie());
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogOutNullWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(Arrays.asList("http*://www.google.com"));
        setLogout(logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"))
                .andExpect(emptyCurrentUserCookie());
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogOutEmptyWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(EMPTY_LIST);
        setLogout(logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").param("redirect", "https://www.google.com").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/login"))
                .andExpect(emptyCurrentUserCookie());
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogoutRedirectIsEnabledInZone() throws Exception {
        String zoneId = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        zone.setConfig(new IdentityZoneConfiguration());
        IdentityZoneProvisioning provisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        zone = provisioning.create(zone);
        assertFalse(zone.getConfig().getLinks().getLogout().isDisableRedirectParameter());
    }

    @Test
    public void testLogOutChangeUrlValue() throws Exception {
        Links.Logout original = getLogout();
        assertFalse(original.isDisableRedirectParameter());
        Links.Logout logout = getLogout();
        logout.setRedirectUrl("https://www.google.com");
        setLogout(logout);
        try {
            mockMvc.perform(get("/uaa/logout.do").contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"))
                .andExpect(emptyCurrentUserCookie());
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogOutWithClientRedirect() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(EMPTY_LIST);
        setLogout(logout);
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
            setLogout(original);
        }
    }

    @Test
    public void testLogOut_Config_For_Zone() throws Exception {
        String zoneId = new RandomValueStringGenerator().generate();
        IdentityZoneProvisioning zoneProvisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        zone.setName(zoneId).setConfig(new IdentityZoneConfiguration());
        zone.getConfig().getLinks().getLogout()
            .setRedirectUrl("http://test.redirect.com")
            .setDisableRedirectParameter(true)
            .setRedirectParameterName("redirect");
        zone = zoneProvisioning.create(zone);

        //default zone
        mockMvc.perform(get("/uaa/logout.do").contextPath("/uaa"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/uaa/login"))
            .andExpect(emptyCurrentUserCookie());

        //other zone
        mockMvc.perform(get("/uaa/logout.do")
            .contextPath("/uaa")
            .header("Host", zoneId+".localhost"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://test.redirect.com"))
            .andExpect(emptyCurrentUserCookie());

        mockMvc.perform(get("/uaa/logout.do")
                                .contextPath("/uaa")
                                 .header("Host", zoneId+".localhost")
                                 .param("redirect", "http://google.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://test.redirect.com"))
            .andExpect(emptyCurrentUserCookie());

        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone = zoneProvisioning.update(zone);

        mockMvc.perform(get("/uaa/logout.do")
                                .contextPath("/uaa")
                                .header("Host", zoneId+".localhost")
                                .param("redirect", "http://google.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://test.redirect.com"))
            .andExpect(emptyCurrentUserCookie());

        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone.getConfig().getLinks().getLogout().setWhitelist(asList("http://google.com"));
        zone = zoneProvisioning.update(zone);

        mockMvc.perform(get("/uaa/logout.do")
                                 .contextPath("/uaa")
                                 .header("Host", zoneId+".localhost")
                                 .param("redirect", "http://google.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://google.com"))
            .andExpect(emptyCurrentUserCookie());

        zone.getConfig().getLinks().getLogout().setWhitelist(asList("http://yahoo.com"));
        zone = zoneProvisioning.update(zone);

        mockMvc.perform(get("/uaa/logout.do")
                                .contextPath("/uaa")
                                .header("Host", zoneId+".localhost")
                                .param("redirect", "http://google.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://test.redirect.com"))
            .andExpect(emptyCurrentUserCookie());

        mockMvc.perform(get("/uaa/logout.do")
                                .contextPath("/uaa")
                                .header("Host", zoneId+".localhost")
                                .param("redirect", "http://yahoo.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://yahoo.com"))
            .andExpect(emptyCurrentUserCookie());

    }

    @Nested
    @ExtendWith(SpringExtension.class)
    @ExtendWith(HoneycombJdbcInterceptorExtension.class)
    @ExtendWith(HoneycombAuditEventTestListenerExtension.class)
    @ActiveProfiles("default")
    @WebAppConfiguration
    @ContextConfiguration(classes = TestSpringContext.class)
    @TestPropertySource(properties = {"analytics.code=secret_code", "analytics.domain=example.com"})
    class LoginWithAnalytics {
        @Autowired
        private WebApplicationContext webApplicationContext;

        @BeforeEach
        public void setup() {
            FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
            mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                    .addFilter(springSecurityFilterChain)
                    .build();

        }

        @Test
        public void testLoginWithAnalytics() throws Exception {
            mockMvc.perform(get("/login").accept(TEXT_HTML))
                    .andExpect(status().isOk())
                    .andExpect(xpath("//body/script[contains(text(),'example.com')]").exists());
        }
    }

    @Test
    public void testDefaultBranding() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("/resources/oss/images/square-logo.png"))
                .andExpect(xpath("//head/link[@href='/resources/oss/stylesheets/application.css']").exists())
                .andExpect(xpath("//head/style[text()[contains(.,'/resources/oss/images/product-logo.png')]]").exists());
    }

    @Nested
    @ExtendWith(SpringExtension.class)
    @ExtendWith(HoneycombJdbcInterceptorExtension.class)
    @ExtendWith(HoneycombAuditEventTestListenerExtension.class)
    @ActiveProfiles("default")
    @WebAppConfiguration
    @ContextConfiguration(classes = TestSpringContext.class)
    @TestPropertySource(properties = {"assetBaseUrl=//cdn.example.com/pivotal"})
    class Branding {
        @Autowired
        private WebApplicationContext webApplicationContext;

        @BeforeEach
        public void setup() {
            FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
            mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                    .addFilter(springSecurityFilterChain)
                    .build();
        }

        @Test
        public void testExternalizedBranding() throws Exception {
            mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                    .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("//cdn.example.com/pivotal/images/square-logo.png"))
                    .andExpect(xpath("//head/link[@href='//cdn.example.com/pivotal/stylesheets/application.css']").exists())
                    .andExpect(xpath("//head/style[text()[contains(.,'//cdn.example.com/pivotal/images/product-logo.png')]]").exists());
        }
    }

    @Test
    public void testAccessConfirmationPage() throws Exception {
        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(JdbcScimUserProvisioning.class);
        ScimUser marissa = userProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"", IdentityZoneHolder.get().getId()).get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());

        UaaAuthentication principal = new UaaAuthentication(uaaPrincipal, asList(UaaAuthority.fromAuthorities("uaa.user")), null);
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
    public void testSignupsAndResetPasswordEnabled() throws Exception {
        setSelfServiceLinksEnabled(true);

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").exists())
            .andExpect(xpath("//a[text()='Reset password']").exists());
    }

    @Test
    public void testSignupsAndResetPasswordDisabledWithNoLinksConfigured() throws Exception {
        setSelfServiceLinksEnabled(false);

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    public void testSignupsAndResetPasswordDisabledWithSomeLinksConfigured() throws Exception {
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://example.com/signup");
        identityZoneConfiguration.getLinks().getSelfService().setPasswd("http://example.com/reset_passwd");
        identityZoneConfiguration.getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        setZoneConfiguration(identityZoneConfiguration);
        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    public void testSignupsAndResetPasswordEnabledWithCustomLinks() throws Exception {
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://example.com/signup");
        identityZoneConfiguration.getLinks().getSelfService().setPasswd("http://example.com/reset_passwd");
        identityZoneConfiguration.getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        setZoneConfiguration(identityZoneConfiguration);
        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']/@href").string("http://example.com/signup"))
            .andExpect(xpath("//a[text()='Reset password']/@href").string("http://example.com/reset_passwd"));
    }

    @Test
    public void testLoginWithExplicitPrompts() throws Exception {
        List<Prompt> original = getPrompts();
        try {
            Prompt first = new Prompt("how", "text", "How did I get here?");
            Prompt second = new Prompt("where", "password", "Where does that highway go to?");
            setPrompts(asList(first, second));

            mockMvc.perform(get("/login").accept(TEXT_HTML))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"))
                    .andExpect(model().attribute("prompts", hasKey("how")))
                    .andExpect(model().attribute("prompts", hasKey("where")))
                    .andExpect(model().attribute("prompts", not(hasKey("password"))));
        } finally {
            setPrompts(original);
        }
    }

    @Test
    public void testLoginWithExplicitJsonPrompts() throws Exception {
        List<Prompt> original = getPrompts();
        try {
            Prompt first = new Prompt("how", "text", "How did I get here?");
            Prompt second = new Prompt("where", "password", "Where does that highway go to?");
            setPrompts(asList(first, second));

            mockMvc.perform(get("/login")
                .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("how")))
                .andExpect(model().attribute("prompts", hasKey("where")))
                .andExpect(model().attribute("prompts", not(hasKey("password"))));
        } finally {
            setPrompts(original);
        }
    }


    @Test
    public void testLoginWithRemoteUaaPrompts() throws Exception {
        mockMvc.perform(get("/login")
            .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", not(hasKey("passcode"))))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    public void testLoginWithRemoteUaaJsonPrompts() throws Exception {
        mockMvc.perform(get("/login")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("prompts", hasKey("username")))
            .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    public void testDefaultMfaPrompt() throws Exception {
        IdentityZone zone = createZoneLinksZone();
        zone.getConfig().getMfaConfig().setEnabled(true);
        MockMvcUtils.updateIdentityZone(zone, webApplicationContext);

        mockMvc.perform(
            get("/login")
                .accept(APPLICATION_JSON)
                .header("Host", zone.getSubdomain()+".localhost")
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
    public void testInfoWithRemoteUaaJsonPrompts() throws Exception {
        mockMvc.perform(get("/info")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("prompts", hasKey("username")))
            .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    public void testDefaultAndCustomSignupLink() throws Exception {
        mockMvc.perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(model().attribute("links", hasEntry("createAccountLink", "/create_account")));
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://www.example.com/signup");
        setZoneConfiguration(identityZoneConfiguration);
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "http://www.example.com/signup")));
    }

    @Test
    public void testLocalSignupDisabled() throws Exception {
        setSelfServiceLinksEnabled(false);
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @Test
    public void testCustomSignupLinkWithLocalSignupDisabled() throws Exception {
        setSelfServiceLinksEnabled(false);
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @Test
    public void testSamlLoginLinksShowActiveProviders() throws Exception {
        String activeAlias = "login-saml-"+generator.generate();
        String inactiveAlias = "login-saml-"+generator.generate();

        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(metadata)
            .setIdpEntityAlias(activeAlias)
            .setLinkText("Active SAML Provider")
            .setShowSamlLink(true)
            .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
        activeIdentityProvider.setType(OriginKeys.SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setOriginKey(activeAlias);
        createIdentityProvider(identityZone, activeIdentityProvider);

        metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition inactiveSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(metadata)
            .setIdpEntityAlias(inactiveAlias)
            .setLinkText("You should not see me")
            .setZoneId(identityZone.getId());
        IdentityProvider inactiveIdentityProvider = new IdentityProvider();
        inactiveIdentityProvider.setType(OriginKeys.SAML);
        inactiveIdentityProvider.setName("Inactive SAML Provider");
        inactiveIdentityProvider.setConfig(inactiveSamlIdentityProviderDefinition);
        inactiveIdentityProvider.setActive(false);
        inactiveIdentityProvider.setOriginKey(inactiveAlias);
        createIdentityProvider(identityZone, inactiveIdentityProvider);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + activeSamlIdentityProviderDefinition.getLinkText() + "']").exists())
            .andExpect(xpath("//a[text()='" + inactiveSamlIdentityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testSamlRedirectWhenTheOnlyProvider() throws Exception {
        String alias = "login-saml-"+generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(metadata)
            .setIdpEntityAlias(alias)
            .setLinkText("Active SAML Provider")
            .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
        activeIdentityProvider.setType(OriginKeys.SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setOriginKey(alias);
        createIdentityProvider(identityZone, activeIdentityProvider);

        zoneAdminClient.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(activeIdentityProvider.getOriginKey()));
        MockMvcUtils.updateClient(webApplicationContext, zoneAdminClient, identityZone);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = new MockMvcUtils.MockSavedRequest();
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);

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

        IdentityProviderProvisioning provisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider uaaProvider = provisioning.retrieveByOrigin(UAA, identityZone.getId());
        try {
            IdentityZoneHolder.set(identityZone);
            uaaProvider.setActive(false);
            provisioning.update(uaaProvider, uaaProvider.getIdentityZoneId());
            mockMvc.perform(get("/login")
                .accept(APPLICATION_JSON)
                .session(session)
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());
        }finally {
            IdentityZoneHolder.set(identityZone);
            uaaProvider.setActive(true);
            provisioning.update(uaaProvider, uaaProvider.getIdentityZoneId());
            IdentityZoneHolder.clear();
        }


    }

    @Test
    public void samlRedirect_onlyOneProvider_noClientContext() throws Exception {
        String alias = "login-saml-"+generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(metadata)
            .setIdpEntityAlias(alias)
            .setLinkText("Active SAML Provider")
            .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
        activeIdentityProvider.setType(OriginKeys.SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setOriginKey(alias);
        createIdentityProvider(identityZone, activeIdentityProvider);

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider uaaIdentityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        identityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/saml/discovery?returnIDParam=idp&entityID=" + identityZone.getSubdomain() + ".cloudfoundry-saml-login&idp="+alias+"&isPassive=true"));
        IdentityZoneHolder.clear();
    }

    @Test
    public void xOAuthRedirect_onlyOneProvider_noClientContext_and_ResponseType_Set() throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String oauthAlias = createOIDCProviderInZone(identityZone, zoneAdminToken, null);

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider uaaIdentityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        identityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

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
    public void xOAuthRedirectOnlyOneProviderWithDiscoveryUrl() throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String oauthAlias = createOIDCProviderInZone(identityZone, zoneAdminToken, "https://accounts.google.com/.well-known/openid-configuration");

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider uaaIdentityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        identityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        MvcResult mvcResult = mockMvc.perform(get("/login").accept(TEXT_HTML)
                .servletPath("/login")
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");
        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();

        assertThat(location, startsWith("https://accounts.google.com/o/oauth2/v2/auth"));
        assertThat(queryParams, hasEntry("client_id", "uaa"));
        assertThat(queryParams, hasEntry("response_type", "code+id_token"));
        assertThat(queryParams, hasEntry("redirect_uri", "http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias));
        assertThat(queryParams, hasEntry("scope", "openid+roles"));
        assertThat(queryParams, hasKey("nonce"));

        IdentityZoneHolder.clear();
    }

    @Test
    public void xOauthRedirect_stateParameterPassedGetsReturned() throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String oauthAlias = createOIDCProviderInZone(identityZone, zoneAdminToken, null);

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider uaaIdentityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        identityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

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

    private String createOIDCProviderInZone(IdentityZone identityZone, String zoneAdminToken, String discoveryUrl) throws Exception {
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();


        if(StringUtils.hasText(discoveryUrl)) {
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

        createIdentityProvider(identityZone, oauthIdentityProvider);
        return oauthAlias;
    }

    @Test
    public void testLoginHintRedirect() throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        MockMvcUtils.IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

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

        createIdentityProvider(identityZone, oauthIdentityProvider);

        IdentityZoneHolder.set(identityZone);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(DefaultSavedRequest.class);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[] { "example.com" });
        session.putValue(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);


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
    public void noRedirect_ifProvidersOfDifferentTypesPresent() throws Exception {
        String alias = "login-saml-"+generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setIdpEntityAlias(alias)
                .setLinkText("Active SAML Provider")
                .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
        activeIdentityProvider.setType(OriginKeys.SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(activeSamlIdentityProviderDefinition);
        activeIdentityProvider.setOriginKey(alias);
        activeIdentityProvider = createIdentityProvider(identityZone, activeIdentityProvider);

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

        createIdentityProvider(identityZone, oauthIdentityProvider);

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider uaaIdentityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        identityProviderProvisioning.update(uaaIdentityProvider, uaaIdentityProvider.getIdentityZoneId());

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
        IdentityZoneHolder.clear();
    }

    public IdentityProvider createIdentityProvider(IdentityZone identityZone, IdentityProvider activeIdentityProvider) throws Exception {
        activeIdentityProvider.setIdentityZoneId(identityZone.getId());
        return webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).create(activeIdentityProvider, identityZone.getId());
    }

    @Test
    public void testNoCreateAccountLinksWhenUAAisNotAllowedProvider() throws Exception {
        String alias2 = "login-saml-"+generator.generate();
        String alias3 = "login-saml-"+generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient, false);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition3 = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, "http://example3.com/saml/metadata"))
            .setIdpEntityAlias(alias3)
            .setLinkText("Active3 SAML Provider")
            .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider3 = new IdentityProvider();
        activeIdentityProvider3.setType(OriginKeys.SAML);
        activeIdentityProvider3.setName("Active 3 SAML Provider");
        activeIdentityProvider3.setActive(true);
        activeIdentityProvider3.setConfig(activeSamlIdentityProviderDefinition3);
        activeIdentityProvider3.setOriginKey(alias3);
        activeIdentityProvider3 = createIdentityProvider(identityZone, activeIdentityProvider3);

        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition2 = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, "http://example2.com/saml/metadata"))
            .setIdpEntityAlias(alias2)
            .setLinkText("Active2 SAML Provider")
            .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider2 = new IdentityProvider();
        activeIdentityProvider2.setType(OriginKeys.SAML);
        activeIdentityProvider2.setName("Active 2 SAML Provider");
        activeIdentityProvider2.setActive(true);
        activeIdentityProvider2.setConfig(activeSamlIdentityProviderDefinition2);
        activeIdentityProvider2.setOriginKey(alias2);
        activeIdentityProvider2 = createIdentityProvider(identityZone, activeIdentityProvider2);

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
                    return new String[] {"admin"};
                }
                return new String[0];
            }
            @Override public List<Cookie> getCookies() { return null; }
            @Override public String getMethod() { return null; }
            @Override public List<String> getHeaderValues(String name) { return null; }
            @Override
            public Collection<String> getHeaderNames() { return null; }
            @Override public List<Locale> getLocales() { return null; }
            @Override public Map<String, String[]> getParameterMap() { return null; }
        };
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
            .session(session)
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());


    }

    @Test
    public void testDeactivatedProviderIsRemovedFromSamlLoginLinks() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        String alias = "login-saml-"+generator.generate();
        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(metadata)
            .setIdpEntityAlias(alias)
            .setLinkText("SAML Provider")
            .setShowSamlLink(true)
            .setZoneId(identityZone.getId());
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OriginKeys.SAML);
        identityProvider.setName("SAML Provider");
        identityProvider.setActive(true);
        identityProvider.setConfig(samlIdentityProviderDefinition);
        identityProvider.setOriginKey(alias);

        identityProvider = createIdentityProvider(identityZone, identityProvider);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']").exists());

        identityProvider.setActive(false);
        webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).update(identityProvider, identityZone.getId());

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testChangeEmailWithoutAuthenticationReturnsRedirect() throws Exception {
        mockMvc.perform(get("/change_email").accept(TEXT_HTML))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    public void testChangeEmailPageHasCsrf() throws Exception {
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext);

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));
        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("X-Uaa-Csrf")));
    }

    @Test
    public void testChangeEmailSubmitWithMissingCsrf() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext);

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
    public void testChangeEmailSubmitWithInvalidCsrf() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext);

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
    public void testChangeEmailSubmitWithSpringSecurityForcedCsrf() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext);
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
    public void testChangeEmailSubmitWithCorrectCsrf() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext);

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));

        MvcResult result = mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("X-Uaa-Csrf")))
            .andReturn();

        MockHttpSession session = (MockHttpSession)result.getRequest().getSession();

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
    public void testChangeEmailDoNotLoggedIn() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext);

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
    public void testChangeEmailNoCsrfReturns403AndInvalidRequest() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext);

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
    public void testCsrfForInvitationAcceptPost() throws Exception {
        assumeFalse(isLimitedMode(), "Test only runs in non limited mode.");
        SecurityContext marissaContext = getMarissaSecurityContext(webApplicationContext);
        AnonymousAuthenticationToken inviteToken = new AnonymousAuthenticationToken("invited-test", marissaContext.getAuthentication().getPrincipal(), asList(UaaAuthority.UAA_INVITED));
        MockHttpSession inviteSession = new MockHttpSession();
        SecurityContext inviteContext = new SecurityContextImpl();
        inviteContext.setAuthentication(inviteToken);
        inviteSession.setAttribute("SPRING_SECURITY_CONTEXT", inviteContext);

        Map<String, String> codeData = new HashMap();
        codeData.put("user_id", ((UaaPrincipal)marissaContext.getAuthentication().getPrincipal()).getId());
        codeData.put("email", ((UaaPrincipal)marissaContext.getAuthentication().getPrincipal()).getEmail());
        codeData.put("origin", OriginKeys.UAA);

        ExpiringCode code = webApplicationContext.getBean(ExpiringCodeStore.class).generateCode(JsonUtils.writeValueAsString(codeData), new Timestamp(System.currentTimeMillis() + 1000 * 60), null, IdentityZoneHolder.get().getId());

        //logged in with valid CSRF
        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .session(inviteSession)
            .with(cookieCsrf())
            .param("code",code.getCode())
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
    public void testLogOutCorsPreflight() throws Exception {
        CorsFilter corsFilter = webApplicationContext.getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList("^localhost$", "^*\\.localhost$"));
        corsFilter.setCorsXhrAllowedUris(asList("^/logout\\.do$"));
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
    public void testLogOutCorsPreflightForIdentityZone() throws Exception {
        CorsFilter corsFilter = webApplicationContext.getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList("^localhost$", "^*\\.localhost$"));
        corsFilter.setCorsXhrAllowedUris(asList("^/logout.do$"));
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
    public void testLogOutCorsPreflightWithStandardHeader() throws Exception {
        CorsFilter corsFilter = webApplicationContext.getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList("^localhost$"));
        corsFilter.setCorsXhrAllowedUris(asList("^/logout\\.do$"));
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
    public void testLogOutCorsPreflightWithUnallowedEndpoint() throws Exception {
        CorsFilter corsFilter = webApplicationContext.getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList("^localhost$"));
        corsFilter.setCorsXhrAllowedUris(asList("^/logout\\.do$"));
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
    public void testLogOutCorsPreflightWithUnallowedMethod() throws Exception {
        CorsFilter corsFilter = webApplicationContext.getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList("^localhost$"));
        corsFilter.setCorsXhrAllowedUris(asList("^/logout\\.do$"));
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
    public void testLogOutCorsPreflightWithUnallowedOrigin() throws Exception {
        CorsFilter corsFilter = webApplicationContext.getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList("^localhost$"));
        corsFilter.setCorsXhrAllowedUris(asList("^/logout\\.do$"));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "fuzzybunnies.com");
        mockMvc.perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isForbidden());
    }

    @Test
    public void login_LockoutPolicySucceeds_ForDefaultZone() throws Exception {
        ScimUser userToLockout = createUser(getUaa().getId());
        attemptUnsuccessfulLogin(5, userToLockout.getUserName(), "");
        mockMvc.perform(post("/uaa/login.do")
            .contextPath("/uaa")
            .with(cookieCsrf())
            .param("username", userToLockout.getUserName())
            .param("password", userToLockout.getPassword()))
            .andExpect(redirectedUrl("/uaa/login?error=account_locked"))
            .andExpect(emptyCurrentUserCookie());
    }

    @Test
    public void login_LockoutPolicySucceeds_WhenPolicyIsUpdatedByApi() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, false);

        changeLockoutPolicyForIdpInZone(zone);

        ScimUser userToLockout = createUser(zone.getId());

        attemptUnsuccessfulLogin(2, userToLockout.getUserName(), subdomain);

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
    public void autologin_with_validCode_RedirectsToSavedRequest_ifPresent() throws Exception {
        MockHttpSession session = MockMvcUtils.getSavedRequestSession();

        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

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
    public void autologin_with_validCode_RedirectsToHome() throws Exception {
        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        JdbcExpiringCodeStore store = webApplicationContext.getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

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
    public void idpDiscoveryPageDisplayed_IfFlagIsEnabled() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(config);
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
    public void idpDiscoveryPageNotDisplayed_IfFlagIsEnabledAndDiscoveryUnsuccessfulPreviously() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(config);

        mockMvc.perform(get("/login?discoveryPerformed=true")
            .header("Accept", TEXT_HTML)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(view().name("idp_discovery/password"));
    }

    @Test
    public void idpDiscoveryClientNameDisplayed_WithUTF8Characters() throws Exception {
        String utf8String = "\u7433\u8D3A";
        String clientName = "woohoo-"+utf8String;
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(config);

        MockHttpSession session = new MockHttpSession();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, clientName);
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedRequest savedRequest = getSavedRequest(client);
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);

        mockMvc.perform(get("/login")
            .session(session)
            .header("Accept", TEXT_HTML)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(view().name("idp_discovery/email"))
            .andExpect(content().string(containsString("Sign in to continue to "+clientName)))
            .andExpect(xpath("//input[@name='email']").exists())
            .andExpect(xpath("//div[@class='action']//a").string("Create account"))
            .andExpect(xpath("//input[@name='commit']/@value").string("Next"));
    }

    @Test
    public void accountChooserEnabled_NoSaveAccounts() throws Exception {
        String clientName = "woohoo";
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(config);

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
    public void accountChooserEnabled() throws Exception {
        String clientName = "woohoo";
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setAccountChooserEnabled(true);
        IdentityZone zone = setupZone(config);

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
    public void emailPageIdpDiscoveryEnabled_SelfServiceLinksDisabled() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setLinks(new Links().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(false)));
        IdentityZone zone = setupZone(config);

        setSelfServiceLinksEnabled(false);

        mockMvc.perform(MockMvcRequestBuilders.get("/login")
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(xpath("//div[@class='action']//a").doesNotExist());
    }

    @Test
    public void idpDiscoveryRedirectsToSamlExternalProvider_withClientContext() throws Exception {
        String subdomain = "test-zone-"+generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false);

        String originKey = generator.generate();
        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

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
    public void idpDiscoveryRedirectsToOIDCProvider() throws Exception {
        String subdomain = "oidc-discovery-"+generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false);

        String originKey = createOIDCProvider(zone, "id_token code");

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
    public void multiple_oidc_providers_use_response_type_in_url() throws Exception {
        String subdomain = "oidc-idp-discovery-multi-"+generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false);

        String originKey = createOIDCProvider(zone);
        String originKey2 = createOIDCProvider(zone,"code id_token");

        mockMvc.perform(get("/login")
                                 .header("Accept", TEXT_HTML)
                                 .servletPath("/login")
                                 .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("http://myauthurl.com?client_id=id&amp;response_type=code&")))
            .andExpect(content().string(containsString("http://myauthurl.com?client_id=id&amp;response_type=code+id_token&")));
    }

    public String createOIDCProvider(IdentityZone zone) throws Exception {
        return createOIDCProvider(zone, null);
    }
    public String createOIDCProvider(IdentityZone zone, String responseType) throws Exception {
        String originKey = generator.generate();
        AbstractXOAuthIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setEmailDomain(asList("test.org"));
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
        identityProvider.setType(OriginKeys.OIDC10);
        identityProvider.setConfig(definition);
        createIdentityProvider(zone, identityProvider);
        return originKey;
    }

    @Test
    public void idpDiscoveryWithNoEmailDomainMatch_withClientContext() throws Exception {
        String subdomain = "test-zone-"+generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false);

        IdentityZoneHolder.set(zone);
        IdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin("uaa", zone.getId());
        identityProvider.setConfig(new AbstractIdentityProviderDefinition().setEmailDomain(Collections.singletonList("totally-different.org")));
        identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

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
    public void idpDiscoveryWithMultipleEmailDomainMatches_withClientContext() throws Exception {
        String subdomain = "test-zone-"+generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false);

        IdentityZoneHolder.set(zone);
        IdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin("uaa", zone.getId());
        identityProvider.setConfig(new AbstractIdentityProviderDefinition().setEmailDomain(Collections.singletonList("test.org")));
        identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

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
    public void idpDiscoveryWithUaaFallBack_withClientContext() throws Exception {
        String subdomain = "test-zone-"+generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false);

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

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
            .header("Accept",TEXT_HTML)
            .session(session)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(model().attributeExists("zone_name"))
            .andExpect(view().name("login"));
    }

    @Test
    public void idpDiscoveryWithLdap_withClientContext() throws Exception{
        String subdomain = "test-zone-"+generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false);

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(LDAP, zone.getId());
        identityProvider.setType(LDAP);
        identityProvider.setConfig(new LdapIdentityProviderDefinition().setEmailDomain(Collections.singletonList("testLdap.org")));

        createIdentityProvider(zone, identityProvider);

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

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
    public void passwordPageDisplayed_ifUaaIsFallbackIDPForEmailDomain() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(config);
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
    public void passwordPageIdpDiscoveryEnabled_SelfServiceLinksDisabled() throws Exception {
        setSelfServiceLinksEnabled(false);

        mockMvc.perform(post("/login/idp_discovery")
                .with(cookieCsrf())
                .header("Accept", TEXT_HTML)
                .param("email", "marissa@koala.org"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?discoveryPerformed=true&email=marissa%40koala.org"));

        mockMvc.perform(get("/login?discoveryPerformed=true&email=marissa%40koala.org")
                .with(cookieCsrf())
                .header("Accept",TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//div[@class='action pull-right']//a").doesNotExist());
    }

    @Test
    public void userNamePresentInPasswordPage() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(config);
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
    public void authorizeForClientWithIdpNotAllowed() throws Exception {
        String subdomain = "idp-not-allowed-"+generator.generate().toLowerCase();
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone = createOtherIdentityZone(zone.getSubdomain(), mockMvc, webApplicationContext, false);
        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone = webApplicationContext.getBean(IdentityZoneProvisioning.class).update(zone);

        ScimUser user = createUser(zone.getId());
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
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, asList("a-different-provider"));
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

        String expectedUrl = "http://"+subdomain+".localhost/oauth/authorize?client_id=different-provider-client&response_type=code&client_secret=secret&garbage=this-should-be-preserved";
        String html = mockMvc.perform(authorize)
            .andDo(print())
            .andExpect(status().isUnauthorized())
            .andReturn().getResponse().getContentAsString();
        String extractPattern = "logout.do\\?redirect\\=(.*?)\">click here<";
        Pattern pattern = Pattern.compile(extractPattern);
        Matcher matcher = pattern.matcher(html);
        assertTrue(matcher.find());
        String group = matcher.group(1);
        assertEquals(expectedUrl, URLDecoder.decode(group, "UTF-8"));
    }

    private MockHttpSession setUpClientAndProviderForIdpDiscovery(String originKey, IdentityZone zone) throws Exception {
        String metadata = String.format(MockMvcUtils.IDP_META_DATA, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition config = (SamlIdentityProviderDefinition) new SamlIdentityProviderDefinition()
            .setMetaDataLocation(metadata)
            .setIdpEntityAlias(originKey)
            .setLinkText("Active SAML Provider")
            .setZoneId(zone.getId())
            .setEmailDomain(Collections.singletonList("test.org"));

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(originKey, zone.getId());
        identityProvider.setType(OriginKeys.SAML);
        identityProvider.setConfig(config);
        createIdentityProvider(zone, identityProvider);

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "woohoo");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, asList(originKey, "other-provider", UAA, LDAP));
        MockMvcUtils.createClient(webApplicationContext, client, zone);

        SavedRequest savedRequest = getSavedRequest(client);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);
        return session;
    }

    private void changeLockoutPolicyForIdpInZone(IdentityZone zone) throws Exception {
        IdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, zone.getId());

        LockoutPolicy policy = new LockoutPolicy();
        policy.setLockoutAfterFailures(2);
        policy.setLockoutPeriodSeconds(3600);
        policy.setCountFailuresWithin(900);

        UaaIdentityProviderDefinition configMap = new UaaIdentityProviderDefinition(null, policy);

        identityProvider.setConfig(configMap);

        webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).update(identityProvider, zone.getId());
    }

    private void attemptUnsuccessfulLogin(int numberOfAttempts, String username, String subdomain) throws Exception {
        String requestDomain = subdomain.equals("") ? "localhost" : subdomain + ".localhost";
        MockHttpServletRequestBuilder post = post("/uaa/login.do")
            .with(new SetServerNameRequestPostProcessor(requestDomain))
            .with(cookieCsrf())
            .contextPath("/uaa")
            .param("username", username)
            .param("password", "wrong_password");
        for (int i = 0; i < numberOfAttempts ; i++) {
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

    private IdentityZone setupZone(IdentityZoneConfiguration config) throws Exception {
        String zoneId = generator.generate().toLowerCase();
        IdentityZone zone = createOtherIdentityZone(zoneId, mockMvc, webApplicationContext, false);
        zone.setConfig(config);
        webApplicationContext.getBean(IdentityZoneProvisioning.class).update(zone);
        return zone;
    }

    private SavedRequest getSavedRequest(BaseClientDetails client) throws Exception {
        return new DefaultSavedRequest(new MockHttpServletRequest(), new PortResolverImpl()) {
            @Override
            public String getRedirectUrl() {
                return "http://test/redirect/oauth/authorize";
            }
            @Override
            public String[] getParameterValues(String name) {
                if ("client_id".equals(name)) {
                    return new String[] {client.getClientId()};
                }
                return new String[0];
            }
            @Override public List<Cookie> getCookies() { return null; }
            @Override public String getMethod() { return null; }
            @Override public List<String> getHeaderValues(String name) { return null; }
            @Override
            public Collection<String> getHeaderNames() { return null; }
            @Override public List<Locale> getLocales() { return null; }
            @Override public Map<String, String[]> getParameterMap() { return null; }
        };
    }

    public boolean isLimitedMode() throws Exception {
        return webApplicationContext.getBean(LimitedModeUaaFilter.class).isEnabled();
    }
}
