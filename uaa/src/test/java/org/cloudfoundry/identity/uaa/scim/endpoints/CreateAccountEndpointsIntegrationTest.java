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

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.test.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.test.IntegrationTestContextLoader;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.security.SecureRandom;
import java.sql.Timestamp;

import static org.hamcrest.Matchers.nullValue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class, loader = IntegrationTestContextLoader.class)
public class CreateAccountEndpointsIntegrationTest {

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    FilterChainProxy springSecurityFilterChain;

    private MockMvc mockMvc;
    private String loginToken;

    @Before
    public void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();

        TestClient testClient = new TestClient(mockMvc);
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
    }

    @Test
    public void testAnAccountCreation() throws Exception {
        String username = "newUser" + new SecureRandom().nextInt() + "@example.com";

        Timestamp ts = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000)); // 1 hour

        String postJson = "{" +
                "    \"expiresAt\":\"" + ts.getTime() + "\"," +
                "    \"data\":\"{\\\"username\\\":\\\"" + username + "\\\",\\\"client_id\\\":\\\"login\\\"}\"" +
                "}";

        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content(postJson)
                .accept(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        ExpiringCode expiringCode = new ObjectMapper().readValue(result.getResponse().getContentAsByteArray(), ExpiringCode.class);

        post = post("/create_account")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"" + expiringCode.getCode() + "\",\"password\":\"secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.redirect_location").value(nullValue()));
    }
}
