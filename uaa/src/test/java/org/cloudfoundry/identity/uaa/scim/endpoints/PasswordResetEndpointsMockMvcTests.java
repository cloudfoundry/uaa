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
package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class PasswordResetEndpointsMockMvcTests {

    XmlWebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private String loginToken;
    
    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "login.yml,uaa.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();

        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();

        TestClient testClient = new TestClient(mockMvc);
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login", null);
    }

    @After
    public void tearDown() throws Exception {
        webApplicationContext.getBean(Flyway.class).clean();
        webApplicationContext.destroy();
    }

    @Test
    public void testAPasswordReset() throws Exception {
        MockHttpServletRequestBuilder post;

        post = post("/password_resets")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("marissa")
                .accept(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        String responseString = result.getResponse().getContentAsString();
        Map<String,String> response = new ObjectMapper().readValue(responseString, new TypeReference<Map<String, String>>() {
        });

        post = post("/password_change")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"" + response.get("code") + "\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(testAccounts.getUserName()));
    }

    @Test
    public void testAPasswordChange() throws Exception {
        MockHttpServletRequestBuilder post = post("/password_change")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"username\":\""+testAccounts.getUserName()+"\",\"current_password\":\""+testAccounts.getPassword()+"\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(testAccounts.getUserName()));
    }
}
