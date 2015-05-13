/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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


import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.WhitelistLogoutHandler;
import org.cloudfoundry.identity.uaa.authentication.login.LoginInfoEndpoint;
import org.cloudfoundry.identity.uaa.authentication.login.Prompt;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.servlet.http.Cookie;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

public class LoginMockMvcTests extends TestClassNullifier {

    private static MockEnvironment mockEnvironment = new MockEnvironment();

    private static XmlWebApplicationContext webApplicationContext;

    private static FilterChainProxy springSecurityFilterChain;

    private static MockMvc mockMvc;

    private static UaaTestAccounts testAccounts;

    private static MockMvcUtils mockMvcUtils = MockMvcUtils.utils();

    @BeforeClass
    public static void setUpContext() throws Exception {
        SecurityContextHolder.clearContext();
        webApplicationContext = new XmlWebApplicationContext();
        mockEnvironment.setProperty("login.invitationsEnabled", "true");
        webApplicationContext.setEnvironment(mockEnvironment);
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "login.yml,uaa.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        testAccounts = UaaTestAccounts.standard(null);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        webApplicationContext.getBean(Flyway.class).clean();
        webApplicationContext.destroy();
    }

    @Test
    public void testLogin() throws Exception {
        mockMvc.perform(get("/login"))
                        .andExpect(status().isOk())
                        .andExpect(view().name("login"))
                        .andExpect(model().attribute("links", hasEntry("passwd", "/forgot_password")))
                        .andExpect(model().attribute("links", hasEntry("register", "/create_account")))
                        .andExpect(model().attributeExists("prompts"));
    }

    @Test
    public void testLogOut() throws Exception {
        mockMvc.perform(get("/logout.do"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));
    }

    @Test
    public void testLogOutIgnoreRedirectParameter() throws Exception {
        mockMvc.perform(get("/logout.do").param("redirect", "https://www.google.com"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));
    }

    @Test
    public void testLogOutEnableRedirectParameter() throws Exception {
        SimpleUrlLogoutSuccessHandler logoutSuccessHandler = webApplicationContext.getBean(SimpleUrlLogoutSuccessHandler.class);
        logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(false);
        try {
            mockMvc.perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"));
        } finally {
            logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        }
    }

    @Test
    public void testLogOutWhitelistedRedirectParameter() throws Exception {
        WhitelistLogoutHandler logoutSuccessHandler = webApplicationContext.getBean(WhitelistLogoutHandler.class);
        logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(false);
        logoutSuccessHandler.setWhitelist(Arrays.asList("https://www.google.com"));
        try {
            mockMvc.perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"));
        } finally {
            logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        }
    }

    @Test
    public void testLogOutNotWhitelistedRedirectParameter() throws Exception {
        WhitelistLogoutHandler logoutSuccessHandler = webApplicationContext.getBean(WhitelistLogoutHandler.class);
        logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(false);
        logoutSuccessHandler.setWhitelist(Arrays.asList("https://www.yahoo.com"));
        try {
            mockMvc.perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
        } finally {
            logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        }
    }

    @Test
    public void testLogOutNullWhitelistedRedirectParameter() throws Exception {
        WhitelistLogoutHandler logoutSuccessHandler = webApplicationContext.getBean(WhitelistLogoutHandler.class);
        logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(false);
        logoutSuccessHandler.setWhitelist(null);
        try {
            mockMvc.perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"));
        } finally {
            logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        }
    }

    @Test
    public void testLogOutEmptyWhitelistedRedirectParameter() throws Exception {
        WhitelistLogoutHandler logoutSuccessHandler = webApplicationContext.getBean(WhitelistLogoutHandler.class);
        logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(false);
        logoutSuccessHandler.setWhitelist(Collections.<String>emptyList());
        try {
            mockMvc.perform(get("/logout.do").param("redirect", "https://www.google.com"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
        } finally {
            logoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        }
    }

    @Test
    public void testLogOutChangeUrlValue() throws Exception {
        SimpleUrlLogoutSuccessHandler logoutSuccessHandler = webApplicationContext.getBean(SimpleUrlLogoutSuccessHandler.class);
        logoutSuccessHandler.setDefaultTargetUrl("https://www.google.com");
        try {
            mockMvc.perform(get("/logout.do"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("https://www.google.com"));
        } finally {
            logoutSuccessHandler.setDefaultTargetUrl("/login");
        }
    }

    @Test
    public void testLoginWithAnalytics() throws Exception {
        mockEnvironment.setProperty("analytics.code", "secret_code");
        mockEnvironment.setProperty("analytics.domain", "example.com");

        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//body/script[contains(text(),'example.com')]").exists());
    }

    @Test
    public void testDefaultAndExternalizedBranding() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("/resources/oss/images/favicon.ico"))
            .andExpect(xpath("//head/link[@href='/resources/oss/stylesheets/application.css']").exists())
            .andExpect(xpath("//div[@class='header' and contains(@style,'/resources/oss/images/logo.png')]").exists());

        mockEnvironment.setProperty("assetBaseUrl", "//cdn.example.com/pivotal");

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                .andExpect(xpath("//head/link[@rel='shortcut icon']/@href").string("//cdn.example.com/pivotal/images/favicon.ico"))
                .andExpect(xpath("//head/link[@href='//cdn.example.com/pivotal/stylesheets/application.css']").exists())
                .andExpect(xpath("//div[@class='header' and contains(@style,'//cdn.example.com/pivotal/images/logo.png')]").exists());
    }

    @Test
    public void testAccessConfirmationPage() throws Exception {
        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(JdbcScimUserProvisioning.class);
        ScimUser marissa = userProvisioning.query("username eq \"marissa\" and origin eq \"uaa\"").get(0);
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId(), IdentityZoneHolder.get().getId());

        UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, Arrays.asList(UaaAuthority.fromAuthorities("uaa.user")));
        MockHttpSession session = new MockHttpSession();
        SecurityContext securityContext = new SecurityContextImpl();
        securityContext.setAuthentication(principal);
        session.putValue("SPRING_SECURITY_CONTEXT", securityContext);
        MockHttpServletRequestBuilder get = get("/oauth/authorize")
                .accept(TEXT_HTML)
                .param("response_type", "code")
                .param("client_id", "app")
                .param("state", "somestate")
                .param("redirect_uri", "http://example.com")
                .session(session)
            .principal(principal);
        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/oauth/confirm_access"));
    }

    @Test
    public void testSignupsAndResetPasswordEnabled() throws Exception {
        mockEnvironment.setProperty("login.selfServiceLinksEnabled", "true");

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").exists())
            .andExpect(xpath("//a[text()='Reset password']").exists());
    }

    @Test
    public void testSignupsAndResetPasswordDisabledWithNoLinksConfigured() throws Exception {
        mockEnvironment.setProperty("login.selfServiceLinksEnabled", "false");

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    public void testSignupsAndResetPasswordDisabledWithSomeLinksConfigured() throws Exception {
        mockEnvironment.setProperty("login.selfServiceLinksEnabled", "false");
        mockEnvironment.setProperty("links.signup", "http://example.com/signup");
        mockEnvironment.setProperty("links.passwd", "http://example.com/reset_passwd");

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    public void testSignupsAndResetPasswordEnabledWithCustomLinks() throws Exception {
        mockEnvironment.setProperty("login.selfServiceLinksEnabled", "true");
        mockEnvironment.setProperty("links.signup", "http://example.com/signup");
        mockEnvironment.setProperty("links.passwd", "http://example.com/reset_passwd");

        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
            .andExpect(xpath("//a[text()='Create account']/@href").string("http://example.com/signup"))
            .andExpect(xpath("//a[text()='Reset password']/@href").string("http://example.com/reset_passwd"));
    }

    @Test
    public void testLoginWithExplicitPrompts() throws Exception {
        LoginInfoEndpoint controller = webApplicationContext.getBean(LoginInfoEndpoint.class);
        List<Prompt> original = controller.getPrompts();
        try {
            Prompt first = new Prompt("how", "text", "How did I get here?");
            Prompt second = new Prompt("where", "password", "Where does that highway go to?");
            controller.setPrompts(Arrays.asList(first, second));

            mockMvc.perform(get("/login").accept(TEXT_HTML))
                    .andExpect(status().isOk())
                    .andExpect(view().name("login"))
                    .andExpect(model().attribute("prompts", hasKey("how")))
                    .andExpect(model().attribute("prompts", hasKey("where")))
                    .andExpect(model().attribute("prompts", not(hasKey("password"))));
        } finally {
            controller.setPrompts(original);
        }
    }

    @Test
    public void testLoginWithExplicitJsonPrompts() throws Exception {
        LoginInfoEndpoint controller = webApplicationContext.getBean(LoginInfoEndpoint.class);
        List<Prompt> original = controller.getPrompts();
        try {
            Prompt first = new Prompt("how", "text", "How did I get here?");
            Prompt second = new Prompt("where", "password", "Where does that highway go to?");
            controller.setPrompts(Arrays.asList(first, second));

            mockMvc.perform(get("/login")
                .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attribute("prompts", hasKey("how")))
                .andExpect(model().attribute("prompts", hasKey("where")))
                .andExpect(model().attribute("prompts", not(hasKey("password"))));
        } finally {
            controller.setPrompts(original);
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
            .andExpect(model().attribute("prompts", hasKey("passcode")))
            .andExpect(model().attribute("prompts", hasKey("password")));
    }

    @Test
    public void testInfoWithRemoteUaaJsonPrompts() throws Exception {
        mockMvc.perform(get("/info")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.prompts[0].name").value("username"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.prompts[1].name").value("password"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.prompts[2].name").value("passcode"));

    }

    @Test
    public void testInfoWithRemoteUaaHtmlPrompts() throws Exception {
        mockMvc.perform(get("/info")
            .accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("prompts", hasKey("username")))
            .andExpect(model().attribute("prompts", not(hasKey("passcode"))))
            .andExpect(model().attribute("prompts", hasKey("password")));
    }


    @Test
    public void testDefaultAndCustomSignupLink() throws Exception {
        mockMvc.perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(model().attribute("createAccountLink", "/create_account"));
        mockEnvironment.setProperty("links.signup", "http://www.example.com/signup");
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", "http://www.example.com/signup"));
    }

    @Test
    public void testLocalSignupDisabled() throws Exception {
        mockEnvironment.setProperty("login.selfServiceLinksEnabled", "false");
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @Test
    public void testCustomSignupLinkWithLocalSignupDisabled() throws Exception {
        mockEnvironment.setProperty("login.selfServiceLinksEnabled", "false");
        mockEnvironment.setProperty("links.signup", "http://www.example.com/signup");
        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("createAccountLink", nullValue()));
    }

    @Test
    public void testSamlLoginLinksShowActiveProviders() throws Exception {
        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        IdentityProviderDefinition activeIdentityProviderDefinition = new IdentityProviderDefinition("http://example.com/saml/metadata", "active-saml", null, 0, false, true, "Active SAML Provider", null, identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
        activeIdentityProvider.setType(Origin.SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(JsonUtils.writeValueAsString(activeIdentityProviderDefinition));
        activeIdentityProvider.setOriginKey("active-saml");
        mockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, activeIdentityProvider, status().isCreated());

        IdentityProviderDefinition inactiveIdentityProviderDefinition = new IdentityProviderDefinition("http://example.com/saml/metadata", "inactive-saml", null, 0, false, true, "You should not see me", null, identityZone.getId());
        IdentityProvider inactiveIdentityProvider = new IdentityProvider();
        inactiveIdentityProvider.setType(Origin.SAML);
        inactiveIdentityProvider.setName("Inactive SAML Provider");
        inactiveIdentityProvider.setActive(false);
        inactiveIdentityProvider.setConfig(JsonUtils.writeValueAsString(inactiveIdentityProviderDefinition));
        inactiveIdentityProvider.setOriginKey("inactive-saml");
        mockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, inactiveIdentityProvider, status().isCreated());

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + activeIdentityProviderDefinition.getLinkText() + "']").exists())
            .andExpect(xpath("//a[text()='" + inactiveIdentityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testSamlRedirectWhenTheOnlyProvider() throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        IdentityProviderDefinition activeIdentityProviderDefinition = new IdentityProviderDefinition("http://example.com/saml/metadata", "active-saml", null, 0, false, true, "Active SAML Provider", null, identityZone.getId());
        IdentityProvider activeIdentityProvider = new IdentityProvider();
        activeIdentityProvider.setType(Origin.SAML);
        activeIdentityProvider.setName("Active SAML Provider");
        activeIdentityProvider.setActive(true);
        activeIdentityProvider.setConfig(JsonUtils.writeValueAsString(activeIdentityProviderDefinition));
        activeIdentityProvider.setOriginKey("active-saml");
        activeIdentityProvider = mockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, activeIdentityProvider, status().isCreated());

        zoneAdminClient.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(activeIdentityProvider.getOriginKey()));
        mockMvcUtils.updateClient(mockMvc, zoneAdminToken, zoneAdminClient, identityZone);

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

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
            .session(session)
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("saml/discovery?returnIDParam=idp&entityID=" + identityZone.getSubdomain() + ".cloudfoundry-saml-login&idp=active-saml&isPassive=true"));
    }

    @Test
    public void testNoCreateAccountLinksWhenUAAisNotAllowedProvider() throws Exception {
        final String zoneAdminClientId = "admin";
        BaseClientDetails zoneAdminClient = new BaseClientDetails(zoneAdminClientId, null, "openid", "client_credentials,authorization_code", "clients.admin,scim.read,scim.write","http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        IdentityProviderDefinition activeIdentityProviderDefinition3 = new IdentityProviderDefinition("http://example3.com/saml/metadata", "active3-saml", null, 0, false, true, "Active3 SAML Provider", null, identityZone.getId());
        IdentityProvider activeIdentityProvider3 = new IdentityProvider();
        activeIdentityProvider3.setType(Origin.SAML);
        activeIdentityProvider3.setName("Active 3 SAML Provider");
        activeIdentityProvider3.setActive(true);
        activeIdentityProvider3.setConfig(JsonUtils.writeValueAsString(activeIdentityProviderDefinition3));
        activeIdentityProvider3.setOriginKey("active3-saml");
        activeIdentityProvider3 = mockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, activeIdentityProvider3, status().isCreated());

        IdentityProviderDefinition activeIdentityProviderDefinition2 = new IdentityProviderDefinition("http://example2.com/saml/metadata", "active2-saml", null, 0, false, true, "Active2 SAML Provider", null, identityZone.getId());
        IdentityProvider activeIdentityProvider2 = new IdentityProvider();
        activeIdentityProvider2.setType(Origin.SAML);
        activeIdentityProvider2.setName("Active 2 SAML Provider");
        activeIdentityProvider2.setActive(true);
        activeIdentityProvider2.setConfig(JsonUtils.writeValueAsString(activeIdentityProviderDefinition2));
        activeIdentityProvider2.setOriginKey("active2-saml");
        activeIdentityProvider2 = mockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, activeIdentityProvider2, status().isCreated());

        zoneAdminClient.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList(activeIdentityProvider3.getOriginKey(), activeIdentityProvider2.getOriginKey()));
        mockMvcUtils.updateClient(mockMvc, zoneAdminToken, zoneAdminClient, identityZone);

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

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"))
            .session(session)
            .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='Create account']").doesNotExist())
            .andExpect(xpath("//a[text()='Reset password']").doesNotExist());


    }

    @Test
    public void testDeactivatedProviderIsRemovedFromSamlLoginLinks() throws Exception {
        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null, null, "client_credentials", "clients.admin,scim.read,scim.write");
        zoneAdminClient.setClientSecret("admin-secret");

        IdentityZoneCreationResult identityZoneCreationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult("puppy-" + new RandomValueStringGenerator().generate(), mockMvc, webApplicationContext, zoneAdminClient);
        IdentityZone identityZone = identityZoneCreationResult.getIdentityZone();
        String zoneAdminToken = identityZoneCreationResult.getZoneAdminToken();

        IdentityProviderDefinition identityProviderDefinition = new IdentityProviderDefinition("http://example.com/saml/metadata", "saml", null, 0, false, true, "SAML Provider", null, identityZone.getId());
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(Origin.SAML);
        identityProvider.setName("SAML Provider");
        identityProvider.setActive(true);
        identityProvider.setConfig(JsonUtils.writeValueAsString(identityProviderDefinition));
        identityProvider.setOriginKey("saml");

        identityProvider = mockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, identityProvider, status().isCreated());

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + identityProviderDefinition.getLinkText() + "']").exists());

        identityProvider.setActive(false);
        mockMvcUtils.createIdpUsingWebRequest(mockMvc, identityZone.getId(), zoneAdminToken, identityProvider, status().isOk(), true);

        mockMvc.perform(get("/login").accept(TEXT_HTML).with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + identityProviderDefinition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testChangeEmailWithoutAuthenticationReturnsRedirect() throws Exception {
        mockMvc.perform(get("/change_email").accept(TEXT_HTML))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    public void testChangeEmailPageHasCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));
        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("_csrf")));
    }

    @Test
    public void testChangeEmailSubmitWithMissingCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));
        MockHttpSession session = (MockHttpSession)mockMvc.perform(get)
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
        mockMvc.perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testChangeEmailSubmitWithInvalidCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));
        MockHttpSession session = (MockHttpSession)mockMvc.perform(get)
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
        mockMvc.perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testChangeEmailSubmitWithSpringSecurityForcedCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);
        //example shows to to test a request that is secured by csrf and you wish to bypass it
        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext))
            .with(csrf())
            .param("newEmail", "test@test.org")
            .param("client_id", "");

        mockMvc.perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("email_sent?code=email_change"));
    }

    @Test
    public void testChangeEmailSubmitWithCorrectCsrf() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));

        MvcResult result = mockMvc.perform(get)
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
        mockMvc.perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("email_sent?code=email_change"));

    }

    @Test
    public void testChangeEmailDoNotLoggedIn() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(csrf());
        mockMvc.perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login"));

        changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(csrf().useInvalidToken());
        mockMvc.perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));

        changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(csrf().useInvalidToken())
            .with(securityContext(marissaContext));
        mockMvc.perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testChangeEmailNoCsrfReturns403AndInvalidRequest() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);

        MockHttpServletRequestBuilder get = get("/change_email")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext));

        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("_csrf")))
            .andReturn();

        MockHttpServletRequestBuilder changeEmail = post("/change_email.do")
            .accept(TEXT_HTML)
            .with(securityContext(marissaContext))
            .param("newEmail", "test@test.org")
            .param("client_id", "");
        mockMvc.perform(changeEmail)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));
    }

    @Test
    public void testCsrfForInvitationPost() throws Exception {
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);

        //logged in with valid CSRF
        MockHttpServletRequestBuilder post = post("/invitations/new.do")
            .with(securityContext(marissaContext))
            .with(csrf())
            .param("email", generator.generate()+"@example.com");

        mockMvc.perform(post)
            .andDo(print())
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("sent"));

        //logged in, invalid CSRF
        post = post("/invitations/new.do")
            .with(securityContext(marissaContext))
            .with(csrf().useInvalidToken())
            .param("email", generator.generate()+"@example.com");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));

        //not logged in, no CSRF
        post = post("/invitations/new.do")
            .param("email", generator.generate()+"@example.com");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));

        //not logged in, valid CSRF(can't happen)
        post = post("/invitations/new.do")
            .with(csrf())
            .param("email", generator.generate()+"@example.com");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login"));

    }

    @Test
    public void testCsrfForInvitationAcceptPost() throws Exception {
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(webApplicationContext);

        //logged in with valid CSRF
        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .with(securityContext(marissaContext))
            .with(csrf())
            .param("client_id", "random")
            .param("password", "password")
            .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
            .andDo(print())
            .andExpect(status().isUnprocessableEntity());

        //logged in, invalid CSRF
        post = post("/invitations/accept.do")
            .with(securityContext(marissaContext))
            .with(csrf().useInvalidToken())
            .param("client_id", "random")
            .param("password", "password")
            .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));

        //not logged in, no CSRF
        post = post("/invitations/accept.do")
            .param("client_id", "random")
            .param("password", "password")
            .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/invalid_request"));

        //not logged in, valid CSRF(can't happen)
        post = post("/invitations/accept.do")
            .with(csrf())
            .param("client_id", "random")
            .param("password", "password")
            .param("password_confirmation", "yield_unprocessable_entity");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login"));

    }

}
