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

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderConfiguratorTests;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.env.MockPropertySource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import static java.util.Arrays.asList;
import static java.util.Collections.EMPTY_LIST;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createOtherIdentityZone;
import static org.cloudfoundry.identity.uaa.zone.IdentityZone.getUaa;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

public class LoginMockMvcTests extends InjectedMockContextTest {

    private static MockMvcUtils mockMvcUtils = MockMvcUtils.utils();

    private MockEnvironment mockEnvironment;

    private MockPropertySource propertySource;

    private Properties originalProperties = new Properties();

    Field f = ReflectionUtils.findField(MockEnvironment.class, "propertySource");

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    private String adminToken;
    private XmlWebApplicationContext webApplicationContext;
    private IdentityZoneConfiguration originalConfiguration;
    private IdentityZoneConfiguration identityZoneConfiguration;

    private TestClient testClient;

    @Before
    public void setUpContext() throws Exception {
        testClient = new TestClient(getMockMvc());
        SecurityContextHolder.clearContext();
        webApplicationContext = getWebApplicationContext();
        mockEnvironment = (MockEnvironment) webApplicationContext.getEnvironment();
        f.setAccessible(true);
        propertySource = (MockPropertySource)ReflectionUtils.getField(f, mockEnvironment);
        for (String s : propertySource.getPropertyNames()) {
            originalProperties.put(s, propertySource.getProperty(s));
        }
        adminToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", null, null);
        originalConfiguration = getWebApplicationContext().getBean(IdentityZoneProvisioning.class).retrieve(getUaa().getId()).getConfig();
        identityZoneConfiguration = getWebApplicationContext().getBean(IdentityZoneProvisioning.class).retrieve(getUaa().getId()).getConfig();
    }

    @After
    public void resetGenerator() {
        getWebApplicationContext().getBean(JdbcExpiringCodeStore.class).setGenerator(new RandomValueStringGenerator(24));
    }

    @After
    public void tearDown() throws Exception {
        //restore all properties
        setSelfServiceLinksEnabled(true);
        setDisableInternalUserManagement(false);
        setZoneConfiguration(originalConfiguration);
        mockEnvironment.getPropertySources().remove(MockPropertySource.MOCK_PROPERTIES_PROPERTY_SOURCE_NAME);
        MockPropertySource originalPropertySource = new MockPropertySource(originalProperties);
        ReflectionUtils.setField(f, mockEnvironment, new MockPropertySource(originalProperties));
        mockEnvironment.getPropertySources().addLast(originalPropertySource);
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void testLogin() throws Exception {
        getMockMvc().perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("links", hasEntry("forgotPasswordLink", "/forgot_password")))
            .andExpect(model().attribute("links", hasEntry("createAccountLink", "/create_account")))
            .andExpect(model().attributeExists("prompts"))
            .andExpect(content().string(containsString("/create_account")));
    }

    protected void setDisableInternalAuth(boolean disable) {
       MockMvcUtils.setDisableInternalAuth(getWebApplicationContext(), getUaa().getId(), disable);
    }

    protected void setDisableInternalUserManagement(boolean disabled) {
        MockMvcUtils.setDisableInternalUserManagement(getWebApplicationContext(), getUaa().getId(), disabled);
    }

    protected void setSelfServiceLinksEnabled(boolean enabled) {
        MockMvcUtils.setSelfServiceLinksEnabled(getWebApplicationContext(), getUaa().getId(), enabled);
    }

    protected void setZoneConfiguration(IdentityZoneConfiguration configuration) {
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), getUaa().getId(), configuration);
    }

    protected void setPrompts(List<Prompt> prompts) {
        MockMvcUtils.setPrompts(getWebApplicationContext(), getUaa().getId(), prompts);
    }

    protected List<Prompt> getPrompts() {
        return MockMvcUtils.getPrompts(getWebApplicationContext(), getUaa().getId());
    }

    protected Links.Logout getLogout() {
        return MockMvcUtils.getLogout(getWebApplicationContext(), getUaa().getId());
    }

    protected void setLogout(Links.Logout logout) {
        MockMvcUtils.setLogout(getWebApplicationContext(), getUaa().getId(), logout);
    }


    @Test
    public void test_cookie_csrf() throws Exception {
        MockHttpSession session = new MockHttpSession();

        MockHttpServletRequestBuilder invalidPost = post("/login.do")
            .session(session)
            .param("username", "marissa")
            .param("password", "koala");

        getMockMvc().perform(invalidPost)
            .andDo(print())
            .andExpect(status().isForbidden())
            .andExpect(forwardedUrl("/login?error=invalid_login_request"));

        session = new MockHttpSession();
        String csrfValue = "12345";
        Cookie cookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrfValue);

        getMockMvc().perform(
            invalidPost
                .cookie(cookie)
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, "other-value")
        )
            .andDo(print())
            .andExpect(status().isForbidden())
            .andExpect(forwardedUrl("/login?error=invalid_login_request"));

        MockHttpServletRequestBuilder validPost = post("/login.do")
            .session(session)
            .param("username", "marissa")
            .param("password", "koala")
            .cookie(cookie)
            .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrfValue);
        getMockMvc().perform(validPost)
            .andDo(print())
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));

    }

    @Test
    public void test_case_insensitive_login() throws Exception {
        String username = "mixed-CASE-USER-"+generator.generate()+"@testdomain.com";
        ScimUser user = createUser(username, "", adminToken);
        assertEquals(username, user.getUserName());
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", user.getUserName())
            .param("password", user.getPassword());

        getMockMvc().perform(loginPost)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("\"username\":\"" + user.getUserName())))
            .andExpect(content().string(containsString("\"email\":\"" + user.getPrimaryEmail())));

        loginPost = post("/authenticate")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", user.getUserName().toUpperCase())
            .param("password", user.getPassword());

        getMockMvc().perform(loginPost)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("\"username\":\"" + user.getUserName())))
            .andExpect(content().string(containsString("\"email\":\"" + user.getPrimaryEmail())));
    }

    @Test
    public void testLogin_Post_When_DisableInternalUserManagement_Is_True() throws Exception {
        ScimUser user = createUser("", adminToken);
        setDisableInternalAuth(true);
        try {
            getMockMvc().perform(post("/login.do")
                                     .with(cookieCsrf())
                                     .param("username", user.getUserName())
                                     .param("password", user.getPassword()))
                .andExpect(redirectedUrl("/login?error=login_failure"));
        } finally {
            setDisableInternalAuth(false);
        }
        getMockMvc().perform(post("/login.do")
            .with(cookieCsrf())
            .param("username", user.getUserName())
            .param("password", user.getPassword()))
            .andDo(print())
            .andExpect(redirectedUrl("/"));
    }

    @Test
    public void testLogin_When_DisableInternalUserManagement_Is_True() throws Exception {
        setDisableInternalUserManagement(true);
        getMockMvc().perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attributeExists("prompts"))
            .andExpect(content().string(not(containsString("/create_account"))));
    }

    @Test
    public void testDefaultLogo() throws Exception {
        mockEnvironment.setProperty("assetBaseUrl", "//cdn.example.com/resources");

        getMockMvc().perform(get("/login"))
                .andExpect(content().string(containsString("url(//cdn.example.com/resources/images/product-logo.png)")));
    }

    @Test
    public void testCustomLogo() throws Exception {
        setZoneFavIconAndProductLogo(null, "/bASe/64+");

        getMockMvc().perform(get("/login"))
                .andExpect(content().string(allOf(containsString("url(data:image/png;base64,/bASe/64+)"), not(containsString("url(/uaa/resources/oss/images/product-logo.png)")))));
    }

    @Test
    public void testCustomFavIcon() throws Exception {
        setZoneFavIconAndProductLogo("/sM4lL==", null);

        getMockMvc().perform(get("/login"))
            .andExpect(content().string(allOf(containsString("<link href=\"data:image/png;base64,/sM4lL==\" rel=\"shortcut icon\""), not(containsString("square-logo.png")))));
    }

    @Test
    public void testCustomFavIcon_With_LineBreaks() throws Exception {
        setZoneFavIconAndProductLogo("/sM4\n\nlL==", "/sM4\n\nlL==");

        getMockMvc().perform(get("/login"))
            .andExpect(content().string(allOf(containsString("<link href=\"data:image/png;base64,/sM4\n\nlL==\" rel=\"shortcut icon\""), not(containsString("square-logo.png")))))
            .andExpect(content().string(allOf(containsString("style>.header-image {background-image: url(data:image/png;base64,/sM4lL==);}</style>"), not(containsString("product-logo.png")))));
    }

    private void setZoneFavIconAndProductLogo(String favIcon, String productLogo) {
        BrandingInformation branding = new BrandingInformation();
        branding.setSquareLogo(favIcon);
        branding.setProductLogo(productLogo);
        identityZoneConfiguration.setBranding(branding);
        setZoneConfiguration(identityZoneConfiguration);
    }


    private static final String defaultCopyrightTemplate =  "Copyright &#169; %s";
    private static final String cfCopyrightText = String.format(defaultCopyrightTemplate, "CloudFoundry.org Foundation, Inc.");

    @Test
    public void testDefaultFooter() throws Exception {
        getMockMvc().perform(get("/login"))
                .andExpect(content().string(containsString(cfCopyrightText)));
    }

    @Test
    public void testCustomizedFooter() throws Exception {
        String customFooterText = "This text should be in the footer.";
        BrandingInformation branding = new BrandingInformation();
        branding.setFooterLegalText(customFooterText);
        identityZoneConfiguration.setBranding(branding);
        setZoneConfiguration(identityZoneConfiguration);

        getMockMvc().perform(get("/login"))
                .andExpect(content().string(allOf(containsString(customFooterText), not(containsString(cfCopyrightText)))));
    }

    @Test
    public void testCustomCompanyName() throws Exception {
        String companyName = "Big Company";
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        identityZoneConfiguration.setBranding(branding);
        setZoneConfiguration(identityZoneConfiguration);

        String expectedFooterText = String.format(defaultCopyrightTemplate, companyName);
        getMockMvc().perform(get("/login"))
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

        getMockMvc().perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
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

        getMockMvc().perform(get("/login")).andExpect(content().string(containsString("\n" +
                "          <a href=\"/privacy\">Privacy</a>\n" +
                "          &mdash; <a href=\"/terms.html\">Terms of Use</a>")));
    }

    @Test
    public void testForgotPasswordPageDoesNotHaveCsrf() throws Exception {
        getMockMvc().perform(get("/forgot_password"))
            .andExpect(status().isOk())
            .andExpect(view().name("forgot_password"))
            .andExpect(content().string(containsString("action=\"/forgot_password.do\"")))
            .andExpect(content().string(not(containsString("name=\"_csrf\""))));
    }

    @Test
    public void testForgotPasswordSubmitDoesNotValidateCsrf() throws Exception {
        getMockMvc().perform(
            post("/forgot_password.do")
                .param("email", "marissa@test.org")
                .with(csrf().useInvalidToken()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("email_sent?code=reset_password"));
    }

    @Test
    public void testChangePasswordPageDoesHaveCsrf() throws Exception {
        getMockMvc().perform(
            get("/change_password")
                .with(securityContext(MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext())))
        )
            .andExpect(status().isOk())
            .andExpect(view().name("change_password"))
            .andExpect(content().string(containsString("action=\"/change_password.do\"")))
            .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    @Test
    public void testChangePasswordSubmitDoesValidateCsrf() throws Exception {
        ScimUser user = createUser("", adminToken);
        getMockMvc().perform(
            post("/change_password.do")
                .with(securityContext(MockMvcUtils.utils().getUaaSecurityContext(user.getUserName(), getWebApplicationContext())))
                .param("current_password", user.getPassword())
                .param("new_password", "newSecr3t")
                .param("confirm_password", "newSecr3t")
                .with(csrf().useInvalidToken()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));

        getMockMvc().perform(
            post("/change_password.do")
                .with(securityContext(MockMvcUtils.utils().getUaaSecurityContext(user.getUserName(), getWebApplicationContext())))
                .param("current_password", user.getPassword())
                .param("new_password", "newSecr3t")
                .param("confirm_password", "newSecr3t")
                .with(csrf()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("profile"));
    }

    private ScimUser createUser(String subdomain, String accessToken) throws Exception {
        String username = generator.generate()+"@testdomain.com";
        return createUser(username, subdomain, accessToken);
    }
    private ScimUser createUser(String username, String subdomain, String accessToken) throws Exception {
        ScimUser user = new ScimUser(null, username, "Test", "User");
        user.setPrimaryEmail(username);
        user.setPassword("Secr3t");
        MockMvcUtils.utils().createUserInZone(getMockMvc(), accessToken, user, subdomain);
        return user;
    }

    @Test
    public void testLogOut() throws Exception {
        getMockMvc().perform(get("/logout.do"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));
    }

    @Test
    public void testLogOutIgnoreRedirectParameter() throws Exception {
        getMockMvc().perform(get("/logout.do").param("redirect", "https://www.google.com"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));
    }

    @Test
    public void testLogOutEnableRedirectParameter() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        logout.setDisableRedirectParameter(false);
        setLogout(logout);
        try {
            getMockMvc().perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"));
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
            getMockMvc().perform(get("/logout.do").param("redirect", "http://localhost/internal-location"))
              .andExpect(status().isFound())
              .andExpect(redirectedUrl("http://localhost/internal-location"));
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
            getMockMvc().perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"));
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
            getMockMvc().perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogOutNullWhitelistedRedirectParameter() throws Exception {
        Links.Logout original = getLogout();
        Links.Logout logout = getLogout();
        logout.setDisableRedirectParameter(false);
        logout.setWhitelist(null);
        setLogout(logout);
        try {
            getMockMvc().perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"));
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
            getMockMvc().perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogoutRedirectIsDisabledInZone() throws Exception {
        String zoneId = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        zone.setConfig(new IdentityZoneConfiguration());
        IdentityZoneProvisioning provisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        zone = provisioning.create(zone);
        assertTrue(zone.getConfig().getLinks().getLogout().isDisableRedirectParameter());
    }

    @Test
    public void testLogOutChangeUrlValue() throws Exception {
        Links.Logout original = getLogout();
        assertTrue(original.isDisableRedirectParameter());
        Links.Logout logout = getLogout();
        logout.setRedirectUrl("https://www.google.com");
        setLogout(logout);
        try {
            getMockMvc().perform(get("/logout.do"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"));
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
            String accessToken = mockMvcUtils.getClientOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "");
            BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
            client.setClientSecret(clientId);
            MockMvcUtils.utils().createClient(getMockMvc(), accessToken, client);
            getMockMvc().perform(
                get("/logout.do")
                    .param(CLIENT_ID, clientId)
                    .param("redirect", "http://testing.com")
            )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://testing.com"));

            getMockMvc().perform(
                get("/logout.do")
                    .param(CLIENT_ID, clientId)
                    .param("redirect", "http://www.wildcard.testing")
            )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://www.wildcard.testing"));

            getMockMvc().perform(
                get("/logout.do")
                    .param(CLIENT_ID, "non-existent-client")
                    .param("redirect", "http://www.wildcard.testing")
            )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
        } finally {
            setLogout(original);
        }
    }

    @Test
    public void testLogOut_Config_For_Zone() throws Exception {
        String zoneId = new RandomValueStringGenerator().generate();
        IdentityZoneProvisioning zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        zone.setName(zoneId).setConfig(new IdentityZoneConfiguration());
        zone.getConfig().getLinks().getLogout()
            .setRedirectUrl("http://test.redirect.com")
            .setDisableRedirectParameter(true)
            .setRedirectParameterName("redirect");
        zone = zoneProvisioning.create(zone);

        //default zone
        getMockMvc().perform(get("/logout.do"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));

        //other zone
        getMockMvc().perform(get("/logout.do")
            .header("Host", zoneId+".localhost"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://test.redirect.com"));

        getMockMvc().perform(get("/logout.do")
                                 .header("Host", zoneId+".localhost")
                                 .param("redirect", "http://google.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://test.redirect.com"));

        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        zone = zoneProvisioning.update(zone);

        getMockMvc().perform(get("/logout.do")
                                 .header("Host", zoneId+".localhost")
                                 .param("redirect", "http://google.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://google.com"));

        zone.getConfig().getLinks().getLogout().setWhitelist(asList("http://yahoo.com"));
        zone = zoneProvisioning.update(zone);

        getMockMvc().perform(get("/logout.do")
                                 .header("Host", zoneId+".localhost")
                                 .param("redirect", "http://google.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://test.redirect.com"));

        getMockMvc().perform(get("/logout.do")
                                 .header("Host", zoneId+".localhost")
                                 .param("redirect", "http://yahoo.com")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://yahoo.com"));

    }

    @Test
    public void testLoginWithAnalytics() throws Exception {
        mockEnvironment.setProperty("analytics.code", "secret_code");
        mockEnvironment.setProperty("analytics.domain", "example.com");

        getMockMvc().perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//body/script[contains(text(),'example.com')]").exists());
    }

    @Test
    public void testDefaultAndExternalizedBranding() throws Exception {
        getMockMvc().perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("/resources/oss/images/square-logo.png"))
            .andExpect(xpath("//head/link[@href='/resources/oss/stylesheets/application.css']").exists())
            .andExpect(xpath("//head/style[text()[contains(.,'/resources/oss/images/product-logo.png')]]").exists());

        mockEnvironment.setProperty("assetBaseUrl", "//cdn.example.com/pivotal");

        getMockMvc().perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("//cdn.example.com/pivotal/images/square-logo.png"))
            .andExpect(xpath("//head/link[@href='//cdn.example.com/pivotal/stylesheets/application.css']").exists())
            .andExpect(xpath("//head/style[text()[contains(.,'//cdn.example.com/pivotal/images/product-logo.png')]]").exists());
    }

    @Test
    public void testAccessConfirmationPage() throws Exception {
        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        ScimUser marissa = userProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"").get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());

        UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, asList(UaaAuthority.fromAuthorities("uaa.user")));
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
        getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/oauth/confirm_access"));
    }

    @Test
    public void testSignupsAndResetPasswordEnabled() throws Exception {
        setSelfServiceLinksEnabled(true);

        getMockMvc().perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").exists())
            .andExpect(xpath("//a[text()='Reset password']").exists());
    }

    @Test
    public void testSignupsAndResetPasswordDisabledWithNoLinksConfigured() throws Exception {
        setSelfServiceLinksEnabled(false);

        getMockMvc().perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    public void testSignupsAndResetPasswordDisabledWithSomeLinksConfigured() throws Exception {
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://example.com/signup");
        identityZoneConfiguration.getLinks().getSelfService().setPasswd("http://example.com/reset_passwd");
        identityZoneConfiguration.getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        setZoneConfiguration(identityZoneConfiguration);
        getMockMvc().perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    public void testSignupsAndResetPasswordEnabledWithCustomLinks() throws Exception {
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://example.com/signup");
        identityZoneConfiguration.getLinks().getSelfService().setPasswd("http://example.com/reset_passwd");
        identityZoneConfiguration.getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        setZoneConfiguration(identityZoneConfiguration);
        getMockMvc().perform(MockMvcRequestBuilders.get("/login"))
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

            getMockMvc().perform(get("/login").accept(TEXT_HTML))
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

            getMockMvc().perform(get("/login")
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
        getMockMvc().perform(get("/login")
            .accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("username")))
                .andExpect(model().attribute("prompts", not(hasKey("passcode"))))
                .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    public void testLoginWithRemoteUaaJsonPrompts() throws Exception {
        getMockMvc().perform(get("/login")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("prompts", hasKey("username")))
            .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    public void testInfoWithRemoteUaaJsonPrompts() throws Exception {
        getMockMvc().perform(get("/info")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("prompts", hasKey("username")))
            .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    public void testInfoWithRemoteUaaHtmlPrompts() throws Exception {
        getMockMvc().perform(get("/info")
            .accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("prompts", hasKey("username")))
            .andExpect(model().attribute("prompts", hasKey("password")));
    }


    @Test
    public void testDefaultAndCustomSignupLink() throws Exception {
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(model().attribute("links", hasEntry("createAccountLink", "/create_account")));
        identityZoneConfiguration.getLinks().getSelfService().setSignup("http://www.example.com/signup");
        setZoneConfiguration(identityZoneConfiguration);
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("links", hasEntry("createAccountLink", "http://www.example.com/signup")));
    }

    @Test
    public void testLocalSignupDisabled() throws Exception {
        setSelfServiceLinksEnabled(false);
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @Test
    public void testCustomSignupLinkWithLocalSignupDisabled() throws Exception {
        setSelfServiceLinksEnabled(false);
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @Test
    public void testSamlLoginLinksShowActiveProviders() throws Exception {
        String activeAlias = "login-saml-"+generator.generate();
        String inactiveAlias = "login-saml-"+generator.generate();

        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), getMockMvc(), getWebApplicationContext(), zoneAdminClient);
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
        mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, activeIdentityProvider, status().isCreated());

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
        mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, inactiveIdentityProvider, status().isCreated());

        getMockMvc().perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
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

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), getMockMvc(), getWebApplicationContext(), zoneAdminClient);
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
        activeIdentityProvider = mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, activeIdentityProvider, status().isCreated());

        zoneAdminClient.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(activeIdentityProvider.getOriginKey()));
        mockMvcUtils.updateClient(getMockMvc(), zoneAdminToken, zoneAdminClient, identityZone);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = new MockMvcUtils.MockSavedRequest();
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);

        getMockMvc().perform(get("/login")
            .accept(TEXT_HTML)
            .session(session)
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/saml/discovery?returnIDParam=idp&entityID=" + identityZone.getSubdomain() + ".cloudfoundry-saml-login&idp=" + alias + "&isPassive=true"));

        getMockMvc().perform(get("/login")
            .accept(APPLICATION_JSON)
            .session(session)
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk());

        IdentityProviderProvisioning provisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        IdentityProvider uaaProvider = provisioning.retrieveByOrigin(UAA, identityZone.getId());
        try {
            IdentityZoneHolder.set(identityZone);
            uaaProvider.setActive(false);
            provisioning.update(uaaProvider);
            getMockMvc().perform(get("/login")
                .accept(APPLICATION_JSON)
                .session(session)
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());
        }finally {
            IdentityZoneHolder.set(identityZone);
            uaaProvider.setActive(true);
            provisioning.update(uaaProvider);
            IdentityZoneHolder.clear();
        }


    }

    @Test
    public void samlRedirect_onlyOneProvider_noClientContext() throws Exception {
        String alias = "login-saml-"+generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), getMockMvc(), getWebApplicationContext(), zoneAdminClient);
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
        mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, activeIdentityProvider, status().isCreated());

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        IdentityProvider uaaIdentityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        identityProviderProvisioning.update(uaaIdentityProvider);

        getMockMvc().perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/saml/discovery?returnIDParam=idp&entityID=" + identityZone.getSubdomain() + ".cloudfoundry-saml-login&idp="+alias+"&isPassive=true"));
        IdentityZoneHolder.clear();
    }

    @Test
    public void xOAuthRedirect_onlyOneProvider_noClientContext() throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), getMockMvc(), getWebApplicationContext(), zoneAdminClient);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        XOIDCIdentityProviderDefinition definition = new XOIDCIdentityProviderDefinition();

        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));
        definition.setTokenKey("key");
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        definition.setScopes(asList("openid", "roles"));
        String oauthAlias = "login-oauth-" + generator.generate();

        IdentityProvider<XOIDCIdentityProviderDefinition> oauthIdentityProvider = MultitenancyFixture.identityProvider(oauthAlias, "uaa");
        oauthIdentityProvider.setConfig(definition);
        oauthIdentityProvider.setActive(true);

        mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, oauthIdentityProvider, status().isCreated());

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        IdentityProvider uaaIdentityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        identityProviderProvisioning.update(uaaIdentityProvider);

        getMockMvc().perform(get("/login").accept(TEXT_HTML)
                .servletPath("/login")
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://auth.url?client_id=uaa&response_type=code&redirect_uri=http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias + "&scope=openid+roles"));
        IdentityZoneHolder.clear();
    }

    @Test
    public void testLoginHintRedirect() throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        MockMvcUtils.IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), getMockMvc(), getWebApplicationContext(), zoneAdminClient);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();

        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        XOIDCIdentityProviderDefinition definition = new XOIDCIdentityProviderDefinition();

        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));
        definition.setTokenKey("key");
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        definition.setScopes(asList("openid", "roles"));
        String oauthAlias = "login-oauth-" + generator.generate();

        IdentityProvider<XOIDCIdentityProviderDefinition> oauthIdentityProvider = MultitenancyFixture.identityProvider(oauthAlias, "uaa");
        oauthIdentityProvider.setConfig(definition);
        oauthIdentityProvider.setActive(true);
        oauthIdentityProvider.getConfig().setEmailDomain(singletonList("example.com"));

        MockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, oauthIdentityProvider, status().isCreated());

        IdentityZoneHolder.set(identityZone);

        MockHttpSession session = new MockHttpSession();
        SavedRequest savedRequest = mock(DefaultSavedRequest.class);
        when(savedRequest.getParameterValues("login_hint")).thenReturn(new String[] { "example.com" });
        session.putValue("SPRING_SECURITY_SAVED_REQUEST", savedRequest);


        getMockMvc().perform(get("/login")
                .accept(TEXT_HTML)
                .session(session)
                .servletPath("/login")
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://auth.url?client_id=uaa&response_type=code&redirect_uri=http%3A%2F%2F" + identityZone.getSubdomain() + ".localhost%2Flogin%2Fcallback%2F" + oauthAlias + "&scope=openid+roles"));
        IdentityZoneHolder.clear();



    }

    @Test
    public void noRedirect_ifProvidersOfDifferentTypesPresent() throws Exception {
        String alias = "login-saml-"+generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), getMockMvc(), getWebApplicationContext(), zoneAdminClient);
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
        activeIdentityProvider = mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, activeIdentityProvider, status().isCreated());

        XOIDCIdentityProviderDefinition definition = new XOIDCIdentityProviderDefinition();

        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));
        definition.setTokenKey("key");
        definition.setRelyingPartyId("UAA");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        String oauthAlias = "login-oauth-" + generator.generate();

        IdentityProvider<XOIDCIdentityProviderDefinition> oauthIdentityProvider = MultitenancyFixture.identityProvider(oauthAlias, "uaa");
        oauthIdentityProvider.setConfig(definition);
        oauthIdentityProvider.setActive(true);

        mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, oauthIdentityProvider, status().isCreated());

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        IdentityProvider uaaIdentityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, identityZone.getId());
        uaaIdentityProvider.setActive(false);
        identityProviderProvisioning.update(uaaIdentityProvider);

        getMockMvc().perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
        IdentityZoneHolder.clear();
    }

    @Test
    public void testNoCreateAccountLinksWhenUAAisNotAllowedProvider() throws Exception {
        String alias2 = "login-saml-"+generator.generate();
        String alias3 = "login-saml-"+generator.generate();
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), getMockMvc(), getWebApplicationContext(), zoneAdminClient);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition3 = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderConfiguratorTests.xmlWithoutID, "http://example3.com/saml/metadata"))
            .setIdpEntityAlias(alias3)
            .setLinkText("Active3 SAML Provider")
            .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider3 = new IdentityProvider();
        activeIdentityProvider3.setType(OriginKeys.SAML);
        activeIdentityProvider3.setName("Active 3 SAML Provider");
        activeIdentityProvider3.setActive(true);
        activeIdentityProvider3.setConfig(activeSamlIdentityProviderDefinition3);
        activeIdentityProvider3.setOriginKey(alias3);
        activeIdentityProvider3 = mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, activeIdentityProvider3, status().isCreated());

        SamlIdentityProviderDefinition activeSamlIdentityProviderDefinition2 = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderConfiguratorTests.xmlWithoutID, "http://example2.com/saml/metadata"))
            .setIdpEntityAlias(alias2)
            .setLinkText("Active2 SAML Provider")
            .setZoneId(identityZone.getId());
        IdentityProvider activeIdentityProvider2 = new IdentityProvider();
        activeIdentityProvider2.setType(OriginKeys.SAML);
        activeIdentityProvider2.setName("Active 2 SAML Provider");
        activeIdentityProvider2.setActive(true);
        activeIdentityProvider2.setConfig(activeSamlIdentityProviderDefinition2);
        activeIdentityProvider2.setOriginKey(alias2);
        activeIdentityProvider2 = mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, activeIdentityProvider2, status().isCreated());

        zoneAdminClient.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, asList(activeIdentityProvider3.getOriginKey(), activeIdentityProvider2.getOriginKey()));
        mockMvcUtils.updateClient(getMockMvc(), zoneAdminToken, zoneAdminClient, identityZone);

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
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);

        getMockMvc().perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
            .session(session)
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());


    }

    @Test
    public void testDeactivatedProviderIsRemovedFromSamlLoginLinks() throws Exception {
        String alias = "login-saml-"+generator.generate();
        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), getMockMvc(), getWebApplicationContext(), zoneAdminClient);
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

        identityProvider = mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, identityProvider, status().isCreated());

        getMockMvc().perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']").exists());

        identityProvider.setActive(false);
        mockMvcUtils.createIdpUsingWebRequest(getMockMvc(), identityZone.getId(), zoneAdminToken, identityProvider, status().isOk(), true);

        getMockMvc().perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + samlIdentityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testChangeEmailWithoutAuthenticationReturnsRedirect() throws Exception {
        getMockMvc().perform(get("/change_email").accept(TEXT_HTML))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    public void testChangeEmailPageHasCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));
        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("_csrf")));
    }

    @Test
    public void testChangeEmailSubmitWithMissingCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));
        MockHttpSession session = (MockHttpSession) getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("_csrf")))
            .andReturn().getRequest().getSession();
        assertNotNull(session.getAttribute(HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN")));

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .session(session)
            .with(securityContext(marissaContext))
            .param("newEmail", "test@test.org")
            .param("client_id", "");
        getMockMvc().perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testChangeEmailSubmitWithInvalidCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));
        MockHttpSession session = (MockHttpSession) getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("_csrf")))
            .andReturn().getRequest().getSession();
        assertNotNull(session.getAttribute(HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN")));

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .session(session)
            .with(securityContext(marissaContext))
            .param("newEmail", "test@test.org")
            .param("client_id", "")
            .param("_csrf", "invalid csrf token");
        getMockMvc().perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testChangeEmailSubmitWithSpringSecurityForcedCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());
        //example shows to to test a request that is secured by csrf and you wish to bypass it
        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext))
            .with(csrf())
            .param("newEmail", "test@test.org")
            .param("client_id", "");

        HttpSession session = getMockMvc().perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("email_sent?code=email_change"))
            .andReturn().getRequest().getSession(false);
        System.out.println("session = " + session);
    }

    @Test
    public void testChangeEmailSubmitWithCorrectCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));

        MvcResult result = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("_csrf")))
            .andReturn();

        MockHttpSession session = (MockHttpSession)result.getRequest().getSession();
        CsrfToken csrfToken = (CsrfToken)session.getAttribute(HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN"));

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext))
            .session(session)
            .param("newEmail", "test@test.org")
            .param("client_id", "")
            .param("_csrf", csrfToken.getToken());
        getMockMvc().perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("email_sent?code=email_change"));

    }

    @Test
    public void testChangeEmailDoNotLoggedIn() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(csrf());
        getMockMvc().perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login"));

        changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(csrf().useInvalidToken());
        getMockMvc().perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));

        changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(csrf().useInvalidToken())
            .with(securityContext(marissaContext));
        getMockMvc().perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testChangeEmailNoCsrfReturns403AndInvalidRequest() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("_csrf")))
            .andReturn();

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext))
            .param("newEmail", "test@test.org")
            .param("client_id", "");
        getMockMvc().perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }


    @Test
    public void testCsrfForInvitationAcceptPost() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());
        AnonymousAuthenticationToken inviteToken = new AnonymousAuthenticationToken("invited-test", marissaContext.getAuthentication().getPrincipal(), asList(UaaAuthority.UAA_INVITED));
        MockHttpSession inviteSession = new MockHttpSession();
        SecurityContext inviteContext = new SecurityContextImpl();
        inviteContext.setAuthentication(inviteToken);
        inviteSession.setAttribute("SPRING_SECURITY_CONTEXT", inviteContext);

        //logged in with valid CSRF
        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .session(inviteSession)
            .with(csrf())
            .param("code","thecode")
            .param("client_id", "random")
            .param("password", "password")
            .param("password_confirmation", "yield_unprocessable_entity");

        getMockMvc().perform(post)
            .andExpect(status().isUnprocessableEntity());

        //logged in, invalid CSRF
        post = post("/invitations/accept.do")
            .session(inviteSession)
            .with(csrf().useInvalidToken())
            .param("client_id", "random")
            .param("password", "password")
            .param("password_confirmation", "yield_unprocessable_entity");

        getMockMvc().perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));

        //not logged in, no CSRF
        post = post("/invitations/accept.do")
            .param("client_id", "random")
            .param("password", "password")
            .param("password_confirmation", "yield_unprocessable_entity");

        getMockMvc().perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));


        //not logged in, valid CSRF(can't happen)
        post = post("/invitations/accept.do")
            .with(csrf())
            .param("client_id", "random")
            .param("password", "password")
            .param("code", "notvalidated")
            .param("password_confirmation", "yield_unprocessable_entity");

        getMockMvc().perform(post)
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
        CorsFilter corsFilter = getWebApplicationContext().getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList(new String[] {"^localhost$", "^*\\.localhost$"}));
        corsFilter.setCorsXhrAllowedUris(asList(new String[] {"^/logout\\.do$"}));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "localhost");
        getMockMvc().perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    /**
     * Positive test case that exercises the CORS logic for dealing with the "X-Requested-With" header.
     *
     * @throws Exception
     */
    @Test
    public void testLogOutCorsPreflightForIdentityZone() throws Exception {
        CorsFilter corsFilter = getWebApplicationContext().getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList(new String[] {"^localhost$", "^*\\.localhost$"}));
        corsFilter.setCorsXhrAllowedUris(asList(new String[] {"^/logout.do$"}));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "testzone1.localhost");
        getMockMvc().perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    /**
     * This should avoid the logic for X-Requested-With header entirely.
     *
     * @throws Exception on test failure
     */
    @Test
    public void testLogOutCorsPreflightWithStandardHeader() throws Exception {
        CorsFilter corsFilter = getWebApplicationContext().getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList(new String[] {"^localhost$"}));
        corsFilter.setCorsXhrAllowedUris(asList(new String[] {"^/logout\\.do$"}));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "Accept");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "localhost");
        getMockMvc().perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isOk());
    }

    /**
     * The endpoint is not white-listed to allow CORS requests with the "X-Requested-With" header so the
     * CorsFilter returns a 403.
     *
     * @throws Exception on test failure
     */
    @Test
    public void testLogOutCorsPreflightWithUnallowedEndpoint() throws Exception {
        CorsFilter corsFilter = getWebApplicationContext().getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList(new String[] {"^localhost$"}));
        corsFilter.setCorsXhrAllowedUris(asList(new String[] {"^/logout\\.do$"}));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "localhost");
        getMockMvc().perform(options("/logout.dont").headers(httpHeaders)).andExpect(status().isForbidden());
    }

    /**
     * The access control request method is not a GET therefore CORS requests with the "X-Requested-With"
     * header are not allowed and the CorsFilter returns a 405.
     *
     * @throws Exception on test failure
     */
    @Test
    public void testLogOutCorsPreflightWithUnallowedMethod() throws Exception {
        CorsFilter corsFilter = getWebApplicationContext().getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList(new String[] {"^localhost$"}));
        corsFilter.setCorsXhrAllowedUris(asList(new String[] {"^/logout\\.do$"}));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "POST");
        httpHeaders.add("Origin", "localhost");
        getMockMvc().perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isMethodNotAllowed());
    }

    /**
     * The request origin is not white-listed to allow CORS requests with the "X-Requested-With" header so the
     * CorsFilter returns a 403.
     *
     * @throws Exception on test failure
     */
    @Test
    public void testLogOutCorsPreflightWithUnallowedOrigin() throws Exception {
        CorsFilter corsFilter = getWebApplicationContext().getBean(CorsFilter.class);
        corsFilter.setCorsXhrAllowedOrigins(asList(new String[] {"^localhost$"}));
        corsFilter.setCorsXhrAllowedUris(asList(new String[] {"^/logout\\.do$"}));
        corsFilter.initialize();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Access-Control-Request-Headers", "X-Requested-With");
        httpHeaders.add("Access-Control-Request-Method", "GET");
        httpHeaders.add("Origin", "fuzzybunnies.com");
        getMockMvc().perform(options("/logout.do").headers(httpHeaders)).andExpect(status().isForbidden());
    }

    @Test
    public void login_LockoutPolicySucceeds_ForDefaultZone() throws Exception {
        ScimUser userToLockout = createUser("", adminToken);
        attemptFailedLogin(5, userToLockout.getUserName(), "");
        getMockMvc().perform(post("/login.do")
            .with(cookieCsrf())
            .param("username", userToLockout.getUserName())
            .param("password", userToLockout.getPassword()))
            .andExpect(redirectedUrl("/login?error=account_locked"));
    }

    @Test
    public void login_LockoutPolicySucceeds_WhenPolicyIsUpdatedByApi() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        changeLockoutPolicyForIdpInZone(zone);

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,idps.write", zone.getSubdomain());

        ScimUser userToLockout = createUser(subdomain, zoneAdminToken);

        attemptFailedLogin(2, userToLockout.getUserName(), subdomain);

        getMockMvc().perform(post("/login.do")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .with(cookieCsrf())
            .param("username", userToLockout.getUserName())
            .param("password", userToLockout.getPassword()))
            .andExpect(redirectedUrl("/login?error=account_locked"));
    }

    @Test
    public void autologin_with_validCode_RedirectsToSavedRequest_ifPresent() throws Exception {
        MockHttpSession session = MockMvcUtils.utils().getSavedRequestSession();

        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        AutologinRequest request = new AutologinRequest();
        request.setUsername("marissa");
        request.setPassword("koala");
        getMockMvc().perform(post("/autologin")
                .header("Authorization", "Basic " + new String(new Base64().encode("admin:adminsecret".getBytes())))
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk());

        getMockMvc().perform(get("/autologin")
            .session(session)
            .param("code", "test" + generator.counter.get())
            .param("client_id", "admin"))
            .andExpect(redirectedUrl("http://test/redirect/oauth/authorize"));
    }

    @Test
    public void autologin_with_validCode_RedirectsToHome() throws Exception {
        MockMvcUtils.PredictableGenerator generator = new MockMvcUtils.PredictableGenerator();
        JdbcExpiringCodeStore store = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class);
        store.setGenerator(generator);

        AutologinRequest request = new AutologinRequest();
        request.setUsername("marissa");
        request.setPassword("koala");
        getMockMvc().perform(post("/autologin")
                .header("Authorization", "Basic " + new String(new Base64().encode("admin:adminsecret".getBytes())))
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk());

        getMockMvc().perform(get("/autologin")
            .param("code", "test" + generator.counter.get())
            .param("client_id", "admin"))
                .andExpect(redirectedUrl("home"));
    }

    @Test
    public void idpDiscoveryPageDisplayed_IfFlagIsEnabled() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(config);
        getMockMvc().perform(get("/login")
                .header("Accept", TEXT_HTML)
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk())
                .andExpect(view().name("idp_discovery/email"))
                .andExpect(content().string(containsString("Sign in")))
                .andExpect(xpath("//input[@name='email']").exists())
                .andExpect(xpath("//div[@class='action']//a").string("Create account"))
                .andExpect(xpath("//input[@type='submit']/@value").string("Next"));
    }

    @Test
    public void idpDiscoveryPageNotDisplayed_IfFlagIsEnabledAndDiscoveryFailedPreviously() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        IdentityZone zone = setupZone(config);

        getMockMvc().perform(get("/login?discoveryPerformed=true")
            .header("Accept", TEXT_HTML)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(view().name("login"));
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
        MockMvcUtils.utils().createClient(getMockMvc(), adminToken, client, zone);

        SavedRequest savedRequest = getSavedRequest(client);
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);

        getMockMvc().perform(get("/login")
            .session(session)
            .header("Accept", TEXT_HTML)
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(view().name("idp_discovery/email"))
            .andExpect(content().string(containsString("Sign in to continue to "+clientName)))
            .andExpect(xpath("//input[@name='email']").exists())
            .andExpect(xpath("//div[@class='action']//a").string("Create account"))
            .andExpect(xpath("//input[@type='submit']/@value").string("Next"));
    }

    @Test
    public void emailPageIdpDiscoveryEnabled_SelfServiceLinksDisabled() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setIdpDiscoveryEnabled(true);
        config.setLinks(new Links().setSelfService(new Links.SelfService().setSelfServiceLinksEnabled(false)));
        IdentityZone zone = setupZone(config);

        setSelfServiceLinksEnabled(false);

        getMockMvc().perform(MockMvcRequestBuilders.get("/login")
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(xpath("//div[@class='action']//a").doesNotExist());
    }

    @Test
    public void idpDiscoveryRedirectsToSamlExternalProvider_withClientContext() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("test-saml", "test-saml");
        createOtherIdentityZone(zone.getSubdomain(), getMockMvc(), getWebApplicationContext());

        String originKey = generator.generate();
        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

        getMockMvc().perform(post("/login/idp_discovery")
            .header("Accept", TEXT_HTML)
            .session(session)
            .param("email", "marissa@test.org")
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(redirectedUrl("/saml/discovery?returnIDParam=idp&entityID=" + zone.getSubdomain() + ".cloudfoundry-saml-login&idp=" + originKey + "&isPassive=true"));
    }

    @Test
    public void idpDiscoveryRedirectsToOIDCProvider() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("oidc-idp-discovery", "oidc-idp-discovery");
        createOtherIdentityZone(zone.getSubdomain(), getMockMvc(), getWebApplicationContext());

        String originKey = generator.generate();
        AbstractXOAuthIdentityProviderDefinition definition = new XOIDCIdentityProviderDefinition();
        definition.setEmailDomain(asList("test.org"));
        definition.setAuthUrl(new URL("http://myauthurl.com"));
        definition.setTokenKey("key");
        definition.setTokenUrl(new URL("http://mytokenurl.com"));
        definition.setRelyingPartyId("id");
        definition.setRelyingPartySecret("secret");
        definition.setLinkText("my oidc provider");

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(originKey, zone.getId());
        identityProvider.setType(OriginKeys.OIDC10);
        identityProvider.setConfig(definition);
        MockMvcUtils.createIdpUsingWebRequest(getMockMvc(), zone.getId(), adminToken, identityProvider, status().isCreated());

        getMockMvc().perform(post("/login/idp_discovery")
            .header("Accept", TEXT_HTML)
            .servletPath("/login/idp_discovery")
            .param("email", "marissa@test.org")
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(redirectedUrl("http://myauthurl.com?client_id=id&response_type=code&redirect_uri=http%3A%2F%2Foidc-idp-discovery.localhost%2Flogin%2Fcallback%2F" +originKey));
    }

    @Test
    public void idpDiscoveryWithNoEmailDomainMatch_withClientContext() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("jon", "jon");
        createOtherIdentityZone(zone.getSubdomain(), getMockMvc(), getWebApplicationContext());

        IdentityZoneHolder.set(zone);
        IdentityProviderProvisioning identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin("uaa", zone.getId());
        identityProvider.setConfig(new AbstractIdentityProviderDefinition().setEmailDomain(Collections.singletonList("totally-different.org")));
        identityProviderProvisioning.update(identityProvider);

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

        getMockMvc().perform(post("/login/idp_discovery")
            .header("Accept", TEXT_HTML)
            .session(session)
            .param("email", "marissa@other.domain")
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(redirectedUrl("/login?discoveryPerformed=true"));
    }

    @Test
    public void idpDiscoveryWithMultipleEmailDomainMatches_withClientContext() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("madhura", "madhura");
        createOtherIdentityZone(zone.getSubdomain(), getMockMvc(), getWebApplicationContext());

        IdentityZoneHolder.set(zone);
        IdentityProviderProvisioning identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin("uaa", zone.getId());
        identityProvider.setConfig(new AbstractIdentityProviderDefinition().setEmailDomain(Collections.singletonList("test.org")));
        identityProviderProvisioning.update(identityProvider);

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

        getMockMvc().perform(post("/login/idp_discovery")
            .header("Accept", TEXT_HTML)
            .session(session)
            .param("email", "marissa@test.org")
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(redirectedUrl("/login?discoveryPerformed=true"));
    }

    @Test
    public void idpDiscoveryWithUaaFallBack_withClientContext() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("uaa-fall-back", "uaa-fall-back");
        createOtherIdentityZone(zone.getSubdomain(), getMockMvc(), getWebApplicationContext());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

        getMockMvc().perform(post("/login/idp_discovery")
            .header("Accept", TEXT_HTML)
            .session(session)
            .param("email", "marissa@other.domain")
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(model().attributeExists("zone_name"))
            .andExpect(view().name("idp_discovery/password"));
    }

    @Test
    public void idpDiscoveryWithLdap_withClientContext() throws Exception{
        IdentityZone zone = MultitenancyFixture.identityZone("puppy-ldap", "puppy-ldap");
        createOtherIdentityZone(zone.getSubdomain(), getMockMvc(), getWebApplicationContext());

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(LDAP, zone.getId());
        identityProvider.setType(LDAP);
        identityProvider.setConfig(new LdapIdentityProviderDefinition().setEmailDomain(Collections.singletonList("testLdap.org")));

        MockMvcUtils.createIdpUsingWebRequest(getMockMvc(), zone.getId(), adminToken, identityProvider, status().isCreated());

        String originKey = generator.generate();

        MockHttpSession session = setUpClientAndProviderForIdpDiscovery(originKey, zone);

        getMockMvc().perform(post("/login/idp_discovery")
            .header("Accept", TEXT_HTML)
            .session(session)
            .param("email", "marissa@testLdap.org")
            .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")))
            .andExpect(redirectedUrl("/login?discoveryPerformed=true"));
    }

    @Test
    public void passwordPageDisplayed_ifUaaIsFallbackIDPForEmailDomain() throws Exception {
        getMockMvc().perform(post("/login/idp_discovery")
            .header("Accept", TEXT_HTML)
            .param("email", "marissa@koala.com"))
            .andExpect(status().isOk())
            .andExpect(view().name("idp_discovery/password"))
            .andExpect(xpath("//input[@name='password']").exists())
            .andExpect(xpath("//h4[@id='email']").string("marissa@koala.com"))
            .andExpect(xpath("//div[@class='action pull-right']//a").string("Reset password"))
            .andExpect(xpath("//input[@type='submit']/@value").string("Sign in"));
    }

    @Test
    public void passwordPageIdpDiscoveryEnabled_SelfServiceLinksDisabled() throws Exception {
        setSelfServiceLinksEnabled(false);

        getMockMvc().perform(post("/login/idp_discovery")
            .header("Accept", TEXT_HTML)
            .param("email", "marissa@koala.org"))
            .andExpect(status().isOk())
            .andExpect(xpath("//div[@class='action pull-right']//a").doesNotExist());
    }

    @Test
    public void userNamePresentInPasswordPage() throws Exception {
        getMockMvc().perform(post("/login/idp_discovery")
            .with(cookieCsrf())
            .param("email", "test@email.com"))
            .andExpect(xpath("//input[@name='username']/@value").string("test@email.com"))
            .andExpect(xpath("//input[@name='X-Uaa-Csrf']").exists());
    }

    @Test
    public void authorizeForClientWithIdpNotAllowed() throws Exception {
        String subdomain = "idp-not-allowed";
        IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
        zone.getConfig().getLinks().getLogout().setDisableRedirectParameter(false);
        createOtherIdentityZone(zone.getSubdomain(), getMockMvc(), getWebApplicationContext());

        // log in with some idp
        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,idps.write", zone.getSubdomain());

        ScimUser user = createUser(subdomain, zoneAdminToken);
        MockHttpSession session = new MockHttpSession();

        SetServerNameRequestPostProcessor inZone = new SetServerNameRequestPostProcessor(subdomain + ".localhost");

        MockHttpServletRequestBuilder post = post("/login.do")
          .with(inZone)
          .with(cookieCsrf())
          .session(session)
          .param("username", user.getUserName())
          .param("password", user.getPassword());

        getMockMvc().perform(post)
          .andExpect(redirectedUrl("/"));

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
        MockMvcUtils.utils().createClient(getMockMvc(), adminToken, client, zone);

        MockHttpServletRequestBuilder authorize = get("/oauth/authorize")
          .with(inZone)
          .session(session)
          .param("client_id", "different-provider-client")
          .param("response_type", "code")
          .param("client_secret", "secret")
          .param("garbage", "this-should-be-preserved");

        String expectedMessage = "THE APPLICATION does not support your identity provider. To log into an identity provider supported by the application, <a href=\"/logout.do?redirect=" + URLEncoder.encode("http://idp-not-allowed.localhost/oauth/authorize?client_id=different-provider-client&response_type=code&client_secret=secret&garbage=this-should-be-preserved", "UTF-8") + "\">click here</a>.";
        getMockMvc().perform(authorize)
            .andDo(print())
            .andExpect(status().isUnauthorized())
            .andExpect(content().string(containsString(expectedMessage)));
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
        MockMvcUtils.createIdpUsingWebRequest(getMockMvc(), zone.getId(), adminToken, identityProvider, status().isCreated());

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "uaa.none", "http://*.wildcard.testing,http://testing.com");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "woohoo");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, asList(originKey, "other-provider", UAA, LDAP));
        MockMvcUtils.utils().createClient(getMockMvc(), adminToken, client, zone);

        SavedRequest savedRequest = getSavedRequest(client);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("SPRING_SECURITY_SAVED_REQUEST", savedRequest);
        return session;
    }

    private void changeLockoutPolicyForIdpInZone(IdentityZone zone) throws Exception {
        IdentityProviderProvisioning identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(UAA, zone.getId());

        LockoutPolicy policy = new LockoutPolicy();
        policy.setLockoutAfterFailures(2);
        policy.setLockoutPeriodSeconds(3600);
        policy.setCountFailuresWithin(900);

        UaaIdentityProviderDefinition configMap = new UaaIdentityProviderDefinition(null, policy);

        identityProvider.setConfig(configMap);

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,idps.write", zone.getSubdomain());

        getMockMvc().perform(put("/identity-providers/" + identityProvider.getId())
                .with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost"))
                .content(JsonUtils.writeValueAsString(identityProvider))
                .contentType(APPLICATION_JSON)
                .header("Authorization", "bearer " + zoneAdminToken)).andExpect(status().isOk());
    }

    private void attemptFailedLogin(int numberOfAttempts, String username, String subdomain) throws Exception {
        String requestDomain = subdomain.equals("") ? "localhost" : subdomain + ".localhost";
        MockHttpServletRequestBuilder post = post("/login.do")
            .with(new SetServerNameRequestPostProcessor(requestDomain))
            .with(cookieCsrf())
            .param("username", username)
            .param("password", "wrong_password");
        for (int i = 0; i < numberOfAttempts ; i++) {
            getMockMvc().perform(post)
                .andExpect(redirectedUrl("/login?error=login_failure"));
        }
    }

    private IdentityZone setupZone(IdentityZoneConfiguration config) throws Exception {
        String zoneId = generator.generate().toLowerCase();
        IdentityZone zone = createOtherIdentityZone(zoneId, getMockMvc(), getWebApplicationContext());
        zone.setConfig(config);
        getWebApplicationContext().getBean(IdentityZoneProvisioning.class).update(zone);
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
}
