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
package org.cloudfoundry.identity.uaa.mock.codestore;

import static org.junit.Assert.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.Timestamp;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import com.googlecode.flyway.core.Flyway;

public class ExpiringCodeStoreMockMvcTests {

    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;
    private static TestClient testClient;
    private static String loginToken;

    @BeforeClass
    public static void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = (FilterChainProxy)webApplicationContext.getBean("org.springframework.security.filterChainProxy");

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
                        .build();
        testClient = new TestClient(mockMvc);
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", null, null);
    }

    @AfterClass
    public static void tearDown() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.close();
    }

    @Test
    public void testGenerateCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}");

        String requestBody = new ObjectMapper().writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        mockMvc.perform(post)
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.code").exists())
                        .andExpect(jsonPath("$.expiresAt").value(ts.getTime()))
                        .andExpect(jsonPath("$.data").value("{}"));

    }

    @Test
    public void testGenerateCodeWithInvalidScope() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}");
        TestClient testClient = new TestClient(mockMvc);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.read", null);

        String requestBody = new ObjectMapper().writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        mockMvc.perform(post)
                        .andExpect(status().isForbidden());
    }

    @Test
    public void testGenerateCodeAnonymous() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}");

        String requestBody = new ObjectMapper().writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        mockMvc.perform(post)
                        .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGenerateCodeWithNullData() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null);
        String requestBody = new ObjectMapper().writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        mockMvc.perform(post)
                        .andExpect(status().isBadRequest());

    }

    @Test
    public void testGenerateCodeWithNullExpiresAt() throws Exception {
        ExpiringCode code = new ExpiringCode(null, null, "{}");
        String requestBody = new ObjectMapper().writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        mockMvc.perform(post)
                        .andExpect(status().isBadRequest());

    }

    @Test
    public void testGenerateCodeWithExpiresAtInThePast() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() - 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null);
        String requestBody = new ObjectMapper().writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        mockMvc.perform(post)
                        .andExpect(status().isBadRequest());

    }

    @Test
    public void testRetrieveCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}");
        String requestBody = new ObjectMapper().writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        MvcResult result = mockMvc.perform(post)
                        .andExpect(status().isCreated())
                        .andReturn();

        ExpiringCode rc = new ObjectMapper().readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                        .header("Authorization", "Bearer " + loginToken)
                        .accept(MediaType.APPLICATION_JSON);

        result = mockMvc.perform(get)
                        .andExpect(status().isOk())
                        .andReturn();

        ExpiringCode rc1 = new ObjectMapper().readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        assertEquals(rc, rc1);
    }

    @Test
    public void testRetrieveCodeThatIsExpired() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 1000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}");
        String requestBody = new ObjectMapper().writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        MvcResult result = mockMvc.perform(post)
                        .andExpect(status().isCreated())
                        .andReturn();

        ExpiringCode rc = new ObjectMapper().readValue(result.getResponse().getContentAsString(), ExpiringCode.class);
        Thread.sleep(1001);
        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                        .header("Authorization", "Bearer " + loginToken)
                        .accept(MediaType.APPLICATION_JSON);

        result = mockMvc.perform(get)
                        .andExpect(status().isNotFound())
                        .andReturn();
    }

}
