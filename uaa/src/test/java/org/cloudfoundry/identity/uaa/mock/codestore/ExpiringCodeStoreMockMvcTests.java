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

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.sql.Timestamp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ExpiringCodeStoreMockMvcTests extends InjectedMockContextTest {

    private String loginToken;

    @Before
    public void setUp() throws Exception {
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM expiring_code_store ");
    }

    @Test
    public void testGenerateCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        getMockMvc().perform(post)
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.code").exists())
                        .andExpect(jsonPath("$.expiresAt").value(ts.getTime()))
                        .andExpect(jsonPath("$.data").value("{}"));

    }

    @Test
    public void testGenerateCodeWithInvalidScope() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.read");

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        getMockMvc().perform(post)
                        .andExpect(status().isForbidden());
    }

    @Test
    public void testGenerateCodeAnonymous() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);

        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        getMockMvc().perform(post)
                        .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGenerateCodeWithNullData() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null, null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        getMockMvc().perform(post)
                        .andExpect(status().isBadRequest());

    }

    @Test
    public void testGenerateCodeWithNullExpiresAt() throws Exception {
        ExpiringCode code = new ExpiringCode(null, null, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        getMockMvc().perform(post)
                        .andExpect(status().isBadRequest());

    }

    @Test
    public void testGenerateCodeWithExpiresAtInThePast() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() - 60000);
        ExpiringCode code = new ExpiringCode(null, ts, null, null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        getMockMvc().perform(post)
                        .andExpect(status().isBadRequest());

    }

    @Test
    public void testRetrieveCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        MvcResult result = getMockMvc().perform(post)
                        .andExpect(status().isCreated())
                        .andReturn();

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                        .header("Authorization", "Bearer " + loginToken)
                        .accept(MediaType.APPLICATION_JSON);

        result = getMockMvc().perform(get)
                        .andExpect(status().isOk())
                        .andReturn();

        ExpiringCode rc1 = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        assertEquals(rc, rc1);
    }

    @Test
    public void testRetrieveCodeThatIsExpired() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 1000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
                        .header("Authorization", "Bearer " + loginToken)
                        .contentType(APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(requestBody);

        MvcResult result = getMockMvc().perform(post)
                        .andExpect(status().isCreated())
                        .andReturn();

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);
        expireAllCodes();
        MockHttpServletRequestBuilder get = get("/Codes/" + rc.getCode())
                        .header("Authorization", "Bearer " + loginToken)
                        .accept(MediaType.APPLICATION_JSON);

        result = getMockMvc().perform(get)
                        .andExpect(status().isNotFound())
                        .andReturn();
    }

    @Test
    public void testCodeThatIsExpiredIsDeletedOnCreateOfNewCode() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 1000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .content(requestBody);

        MvcResult result = getMockMvc().perform(post)
            .andExpect(status().isCreated())
            .andReturn();

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        expireAllCodes();

        ts = new Timestamp(System.currentTimeMillis() + 1000);
        code = new ExpiringCode(null, ts, "{}", null);
        requestBody = JsonUtils.writeValueAsString(code);
        post = post("/Codes")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .content(requestBody);

        getMockMvc().perform(post)
            .andExpect(status().isCreated())
            .andReturn();

        assertThat(getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select count(*) from expiring_code_store", Integer.class), is(1));
    }


    @Test
    public void testCodeThatIsExpirationIntervalWorks() throws Exception {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + 1000);
        ExpiringCode code = new ExpiringCode(null, ts, "{}", null);
        String requestBody = JsonUtils.writeValueAsString(code);
        MockHttpServletRequestBuilder post = post("/Codes")
            .header("Authorization", "Bearer " + loginToken)
            .contentType(APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .content(requestBody);

        MvcResult result = getMockMvc().perform(post)
            .andExpect(status().isCreated())
            .andReturn();

        ExpiringCode rc = JsonUtils.readValue(result.getResponse().getContentAsString(), ExpiringCode.class);

        expireAllCodes();
        long interval = getWebApplicationContext().getBean(JdbcExpiringCodeStore.class).getExpirationInterval();
        try {
            getWebApplicationContext().getBean(JdbcExpiringCodeStore.class).setExpirationInterval(10000000);
            ts = new Timestamp(System.currentTimeMillis() + 1000);
            code = new ExpiringCode(null, ts, "{}", null);
            requestBody = JsonUtils.writeValueAsString(code);
            post = post("/Codes")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(requestBody);

            getMockMvc().perform(post)
                .andExpect(status().isCreated())
                .andReturn();

            assertThat(getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select count(*) from expiring_code_store", Integer.class), is(2));
        }finally {
            getWebApplicationContext().getBean(JdbcExpiringCodeStore.class).setExpirationInterval(interval);
        }
    }

    protected void expireAllCodes() throws Exception {
        getWebApplicationContext().getBean(JdbcExpiringCodeStore.class).setExpirationInterval(0);
        Timestamp expired = new Timestamp(System.currentTimeMillis() - 5000);
        getWebApplicationContext().getBean(JdbcTemplate.class).update("update expiring_code_store set expiresat=?", expired.getTime());
    }

}
