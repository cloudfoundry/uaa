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
package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.test.LdapIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(Parameterized.class)
public class LdapMockMvcTests {


    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {"ldap-simple-bind.xml"}, {"ldap-search-and-bind.xml"},{"ldap-search-and-compare.xml"}
        });
    }

    AnnotationConfigWebApplicationContext webApplicationContext;

    MockMvc mockMvc;
    TestClient testClient;

    private String ldapProfile;

    public LdapMockMvcTests(String ldapProfile) {
        this.ldapProfile = ldapProfile;
    }

    @Before
    public void setUp() throws Exception {
        System.setProperty("ldap.profile.file", "ldap/"+ldapProfile);
        webApplicationContext = new AnnotationConfigWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        webApplicationContext.register(LdapIntegrationTestConfig.class);
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();

        List<String> profiles = Arrays.asList(webApplicationContext.getEnvironment().getActiveProfiles());
        Assume.assumeTrue(profiles.contains("ldap"));

        //we need to reinitialize the context if we change the ldap.profile.file property
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
                .build();
        testClient = new TestClient(mockMvc);
    }

    @After
    public void tearDown() throws Exception {
        System.clearProperty("ldap.profile.file");
        webApplicationContext.destroy();
    }

    @Test
    public void printProfileType() {
        Assert.assertEquals(ldapProfile, webApplicationContext.getBean("testLdapProfile"));
    }

    @Test
    public void testLogin() throws Exception {


        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(model().attributeDoesNotExist("saml"));

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .param("username", "marissa")
                        .param("password", "koaladsada"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error=true"));

        mockMvc.perform(post("/login.do").accept(TEXT_HTML_VALUE)
                        .param("username", "marissa2")
                        .param("password", "ldap"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    public void testAuthenticate() throws Exception {
        String username = "marissa3";
        String password = "ldap3";

        MockHttpServletRequestBuilder post =
            post("/authenticate")
            .accept(MediaType.APPLICATION_JSON)
            .param("username", username)
            .param("password", password);

        MvcResult result = mockMvc.perform(post)
            .andExpect(status().isOk())
            .andReturn();

        Assert.assertEquals("{\"username\":\""+username+"\"}", result.getResponse().getContentAsString());
    }

    @Test
    public void testAuthenticateFailure() throws Exception {
        String username = "marissa3";
        String password = "ldapsadadasas";

        MockHttpServletRequestBuilder post =
            post("/authenticate")
                .accept(MediaType.APPLICATION_JSON)
                .param("username",username)
                .param("password",password);

        mockMvc.perform(post)
            .andExpect(status().isUnauthorized());

    }

}
