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


import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;
import java.util.Map;

import static org.hamcrest.Matchers.hasEntry;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

public class LoginMockMvcIntegrationTests {

    XmlWebApplicationContext webApplicationContext;

    FilterChainProxy springSecurityFilterChain;

    private MockMvc mockMvc;

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "login.yml,uaa.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        XFrameOptionsFilter xFrameOptionsFilter = webApplicationContext.getBean(XFrameOptionsFilter.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .addFilter(xFrameOptionsFilter)
            .build();
    }

    @After
    public void tearDown() throws Exception {
        webApplicationContext.destroy();
    }

    @Test
    public void testLogin() throws Exception {
        mockMvc.perform(get("/login"))
                        .andExpect(status().isOk())
                        .andExpect(view().name("login"))
                        .andExpect(model().attribute("links", hasEntry("passwd", "http://localhost:8080/uaa/forgot_password")))
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
    public void testLoginWithEmptyLinks() throws Exception {
        Map<String, String> links = (Map<String, String>) webApplicationContext.getBean("links", Map.class);
        links.put("passwd", "");

        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(model().attribute("links", hasEntry("passwd", "")))
                .andExpect(xpath("//a[text()='Reset password']").doesNotExist());
    }

    @Test
    public void testLoginWithAnalytics() throws Exception {
        System.setProperty("analytics.code", "secret_code");
        System.setProperty("analytics.domain", "example.com");

        mockMvc.perform(get("/login").accept(TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(xpath("//body/script[contains(text(),'example.com')]").exists());
    }
}
