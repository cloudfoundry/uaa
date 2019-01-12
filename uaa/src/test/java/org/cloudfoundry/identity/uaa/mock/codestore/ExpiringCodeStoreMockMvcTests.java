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
package org.cloudfoundry.identity.uaa.mock.codestore;

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.sql.Timestamp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Configuration
class TestClientMockMvc {
    @Bean
    public MockMvc mockMvc(
            WebApplicationContext webApplicationContext,
            FilterChainProxy springSecurityFilterChain
    ) {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();
    }

    @Bean
    public TestClient testClient(
            MockMvc mockMvc
    ) {
        return new TestClient(mockMvc);
    }
}

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(SpringExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = {
        TestSpringContext.class,
        TestClientMockMvc.class
})
@interface DefaultTestContext {
}

@DefaultTestContext
class ExpiringCodeStoreMockMvcTests {

    private String loginToken;

    @Value("${disableInternalUserManagement:false}")
    private boolean disableInternalUserManagement;

    private TestClient testClient;
    private MockMvc mockMvc;
    private JdbcTemplate jdbcTemplate;
    private JdbcExpiringCodeStore jdbcExpiringCodeStore;

    @BeforeEach
    void setUp(@Autowired JdbcTemplate jdbcTemplate,
               @Autowired JdbcExpiringCodeStore jdbcExpiringCodeStore,
               @Autowired MockMvc mockMvc,
               @Autowired TestClient testClient) throws Exception {
        this.jdbcTemplate = jdbcTemplate;
        this.jdbcExpiringCodeStore = jdbcExpiringCodeStore;
        this.mockMvc = mockMvc;
        this.testClient = testClient;
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        jdbcTemplate.update("DELETE FROM expiring_code_store");
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.update("DELETE FROM expiring_code_store");
    }

    @Test
    void testGenerateCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);

        String requestBody = JsonUtils.writeValueAsString(code);
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
    void testGenerateCodeWithInvalidScope() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.read");

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isForbidden());
    }

    @Test
    void testGenerateCodeAnonymous() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testGenerateCodeWithNullData() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null, null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @Test
    void testGenerateCodeWithNullExpiresAt() throws Exception {
        ExpiringCode code = new ExpiringCode(null, null, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @Test
    void testGenerateCodeWithExpiresAtInThePast() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() - 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null, null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());

    }

    @Test
    void testRetrieveCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                .header("Authorization", "Bearer " + loginToken)
                .accept(MediaType.APPLICATION_JSON);

        result = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn();

        ExpiringCode rc1 = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        assertEquals(rc, rc1);
    }

    @Test
    void testRetrieveCodeThatIsExpired() throws Exception {
        Timestamp ts = new Timestamp(Long.MAX_VALUE);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);
        expireAllCodes();
        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                .header("Authorization", "Bearer " + loginToken)
                .accept(MediaType.APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @Test
    void testCodeThatIsExpiredIsDeletedOnCreateOfNewCode() throws Exception {
        Timestamp ts = new Timestamp(Long.MAX_VALUE);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        expireAllCodes();

        ts = new Timestamp(Long.MAX_VALUE);
        code = new ExpiringCode(null, ts, "{}", null);
        requestBody = JsonUtils.writeValueAsString(code);
        post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        assertThat(jdbcTemplate.queryForObject("select count(*) from expiring_code_store", Integer.class), is(1));
    }

    @Nested
    @DefaultTestContext
    class WithCustomExpirationInterval {
        long priorExpirationInterval;

        @BeforeEach
        void setUp() throws Exception {
            // TODO: Why is this here?
            Timestamp ts = new Timestamp(Long.MAX_VALUE);
            ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
            String requestBody = JsonUtils.writeValueAsString(code);
            MockHttpServletRequestBuilder post = post("/Codes")
                    .header("Authorization", "Bearer " + loginToken)
                    .contentType(APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .content(requestBody);

            MvcResult result = mockMvc.perform(post)
                    .andExpect(status().isCreated())
                    .andReturn();

            JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

            expireAllCodes();
            priorExpirationInterval = jdbcExpiringCodeStore.getExpirationInterval();
        }

        @AfterEach
        void tearDown() {
            jdbcExpiringCodeStore.setExpirationInterval(priorExpirationInterval);
        }

        @Test
        void verifyExpirationIntervalWorks() throws Exception {
            jdbcExpiringCodeStore.setExpirationInterval(10000000);
            Timestamp ts = new Timestamp(System.currentTimeMillis() + 1000);
            ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
            String requestBody = JsonUtils.writeValueAsString(code);
            MockHttpServletRequestBuilder post = post("/Codes")
                    .header("Authorization", "Bearer " + loginToken)
                    .contentType(APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .content(requestBody);

            mockMvc.perform(post)
                    .andExpect(status().isCreated())
                    .andReturn();

            assertThat(jdbcTemplate.queryForObject("select count(*) from expiring_code_store", Integer.class), is(2));
        }
    }

    private void expireAllCodes() {
        jdbcExpiringCodeStore.setExpirationInterval(0);
        Timestamp expired = new Timestamp(System.currentTimeMillis() - 5000);
        jdbcTemplate.update("update expiring_code_store set expiresat=?", expired.getTime());
    }

}
