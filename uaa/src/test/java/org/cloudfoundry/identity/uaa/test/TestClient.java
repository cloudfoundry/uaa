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
package org.cloudfoundry.identity.uaa.test;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TestClient {

    //TODO nullify fields?
    private MockMvc mockMvc;

    public TestClient(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    public String getClientCredentialsOAuthAccessToken(String username, String password, String scope) throws Exception {
        return getClientCredentialsOAuthAccessToken(username, password, scope, null);
    }

    public String getClientCredentialsOAuthAccessToken(String username, String password, String scope, String subdomain)
                    throws Exception {
        String basicDigestHeaderValue = "Basic "
                        + new String(Base64.encodeBase64((username + ":" + password).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                        .header("Authorization", basicDigestHeaderValue)
                        .param("grant_type", "client_credentials")
                        .param("client_id", username)
                        .param("scope", scope);
        if (subdomain != null && !subdomain.equals("")) oauthTokenPost.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        MvcResult result = mockMvc.perform(oauthTokenPost)
            .andExpect(status().isOk())
            .andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }

    public String getUserOAuthAccessToken(String clientId, String clientSecret, String username, String password, String scope)
                    throws Exception {
        String basicDigestHeaderValue = "Basic "
                        + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                        .header("Authorization", basicDigestHeaderValue)
                        .param("grant_type", "password")
                        .param("client_id", clientId)
                        .param("username", username)
                        .param("password", password)
                        .param("scope", scope);
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OAuthToken {
        @JsonProperty("access_token")
        public String accessToken;

        public OAuthToken() {
        }
    }
}
