/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.ssl.Base64;
import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.UaaTokenServicesTests.PASSWORD;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class CheckTokenEndpointMockMvcTest extends AbstractTokenMockMvcTests {

    public static final String CLIENTID = "oauth_showcase_password_grant";
    public static final String CLIENTSECRET = "secret";
    private String token;
    private String basic;
    private boolean allowQueryString;

    @Before
    public void get_token_to_check() throws Exception {
        String username = setUpUserForPasswordGrant();

        String content = getMockMvc().perform(
            post("/oauth/token")
                .param("client_id", CLIENTID)
                .param("client_secret", CLIENTSECRET)
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
                .param("username", username)
                .param("password", SECRET)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        Map<String,Object> tokenMap = JsonUtils.readValue(content, new TypeReference<Map<String, Object>>() {});
        token = (String) tokenMap.get("access_token");
        basic = new String(Base64.encodeBase64((CLIENTID+":"+CLIENTSECRET).getBytes()));
        allowQueryString = getWebApplicationContext().getBean(CheckTokenEndpoint.class).isAllowQueryString();
        getWebApplicationContext().getBean(CheckTokenEndpoint.class).setAllowQueryString(false);
    }

    @After
    public void resetAllowQueryString() throws Exception {
        getWebApplicationContext().getBean(CheckTokenEndpoint.class).setAllowQueryString(allowQueryString);
    }


    @Test
    public void check_token_get() throws Exception {
        check_token(get("/check_token"), status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value("Request method 'GET' not supported"));

    }

    @Test
    public void check_token_put() throws Exception {
        check_token(put("/check_token"), status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value("Request method 'PUT' not supported"));

    }

    @Test
    public void check_token_post() throws Exception {
        check_token(post("/check_token"), status().isOk());
    }

    @Test
    public void check_token_get_when_allowed() throws Exception {
        getWebApplicationContext().getBean(CheckTokenEndpoint.class).setAllowQueryString(true);
        get_check_token(status().isOk());
    }

    @Test
    public void check_token_delete() throws Exception {
        check_token(MockMvcRequestBuilders.delete("/check_token"),status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value("Request method 'DELETE' not supported"));
    }

    @Test
    public void check_token_endpoint_post_query_string() throws Exception {
        getMockMvc().perform(
            post("/check_token?token={token}", token)
                .header("Authorization", "Basic " + basic)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE))
            .andExpect(status().isNotAcceptable())
            .andExpect(header().string(CONTENT_TYPE, "application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.error").value("query_string_not_allowed"))
            .andExpect(jsonPath("$.error_description").value("Parameters must be passed in the body of the request"));
    }

    public ResultActions check_token(MockHttpServletRequestBuilder builder, ResultMatcher matcher) throws Exception {
        return getMockMvc().perform(
            builder
                .header("Authorization", "Basic " + basic)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                .param("token", token))
            .andExpect(matcher)
            .andExpect(header().string(CONTENT_TYPE, "application/json;charset=UTF-8"));
    }

    public ResultActions get_check_token(ResultMatcher matcher) throws Exception {
        return getMockMvc().perform(
            get("/check_token?token={token}", token)
                .header("Authorization", "Basic " + basic)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE))
            .andExpect(matcher)
            .andExpect(header().string(CONTENT_TYPE, "application/json;charset=UTF-8"));
    }
}