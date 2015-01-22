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


import java.util.Arrays;
import java.util.List;

import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.login.LoginInfoEndpoint;
import org.cloudfoundry.identity.uaa.authentication.login.Prompt;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

public class LoginMockMvcIntegrationTests {

    private static MockEnvironment mockEnvironment = new MockEnvironment();

    private static XmlWebApplicationContext webApplicationContext;

    private static FilterChainProxy springSecurityFilterChain;

    private static MockMvc mockMvc;

    private static UaaTestAccounts testAccounts;

    @BeforeClass
    public static void setUpContext() throws Exception {
        SecurityContextHolder.clearContext();
        webApplicationContext = new XmlWebApplicationContext();
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
    public void testLoginNoSaml() throws Exception {
        Assume.assumeFalse("Functionality is disabled by the saml profile", Arrays.asList(webApplicationContext.getEnvironment().getActiveProfiles()).contains("saml"));

        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(model().attributeDoesNotExist("showSamlLoginLink"));
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
        UaaPrincipal uaaPrincipal = new UaaPrincipal(marissa.getId(), marissa.getUserName(), marissa.getPrimaryEmail(), marissa.getOrigin(), marissa.getExternalId());

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

//                .andExpect(model().attributeExists("client_id"))
//                .andExpect(model().attribute("undecided_scopes", hasSize(2)))
//                .andExpect(model().attribute("approved_scopes", hasSize(1)))
//                .andExpect(model().attribute("denied_scopes", hasSize(1)))
//                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
//                .andExpect(xpath("//h1[text()='Application Authorization']").exists())
//                .andExpect(xpath("//input[@type='checkbox' and @name='scope.0' and @value='scope.cloud_controller.write' and @checked='checked']").exists())
//                .andExpect(xpath("//input[@type='checkbox' and @name='scope.1' and @value='scope.scim.userids' and @checked='checked']").exists())
//                .andExpect(xpath("//input[@type='checkbox' and @name='scope.2' and @value='scope.password.write' and @checked='checked']").exists())
//                .andExpect(xpath("//input[@type='checkbox' and @name='scope.3' and @value='scope.cloud_controller.read']").exists())
//                .andExpect(xpath("//input[@type='checkbox' and @name='scope.3' and @value='scope.cloud_controller.read' and @checked='checked']").doesNotExist());
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
    
    // The following tests came from https://github.com/cloudfoundry/login-server/blob/89ced7999c98297b746330499cfec0b0177a76ed/src/test/java/org/cloudfoundry/identity/uaa/login/RemoteUaaControllerMockMvcTests.java
    
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
    
}
