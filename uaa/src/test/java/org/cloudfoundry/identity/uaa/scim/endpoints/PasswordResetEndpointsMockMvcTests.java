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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class PasswordResetEndpointsMockMvcTests extends InjectedMockContextTest {

    private String loginToken;
    private ScimUser user;

    @Before
    public void setUp() throws Exception {
        TestClient testClient = new TestClient(getMockMvc());
        loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", null);
        user = new ScimUser(null, new RandomValueStringGenerator().generate()+"@test.org", "PasswordResetUserFirst", "PasswordResetUserLast");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secret");
        user = MockMvcUtils.utils().createUser(getMockMvc(), adminToken, user);
        user.setPassword("secret");
    }

    @Test
    public void testAPasswordReset() throws Exception {
        MockHttpServletRequestBuilder post;

        post = post("/password_resets")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content(user.getUserName())
                .accept(APPLICATION_JSON);

        MvcResult result = getMockMvc().perform(post)
                .andExpect(status().isCreated())
                .andReturn();

        String responseString = result.getResponse().getContentAsString();
        Map<String,String> response = JsonUtils.readValue(responseString, new TypeReference<Map<String, String>>() {
        });

        post = post("/password_change")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"" + response.get("code") + "\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        getMockMvc().perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(user.getUserName()));
    }

    @Test
    public void testAPasswordChange() throws Exception {
        MockHttpServletRequestBuilder post = post("/password_change")
                .header("Authorization", "Bearer " + loginToken)
                .contentType(APPLICATION_JSON)
                .content("{\"username\":\""+user.getUserName()+"\",\"current_password\":\""+user.getPassword()+"\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        getMockMvc().perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value(user.getUserName()));
    }
}
