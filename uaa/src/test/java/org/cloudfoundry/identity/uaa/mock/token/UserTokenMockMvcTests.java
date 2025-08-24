/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.authentication.AbstractClientParametersAuthenticationFilter.CLIENT_SECRET;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class UserTokenMockMvcTests extends AbstractTokenMockMvcTests {

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private IdentityZoneManager identityZoneManager;

    @Test
    void user_managed_token() throws Exception {
        String recipientId = "recipientClient" + new RandomValueStringGenerator().generate();
        setUpClients(recipientId, "uaa.user", "uaa.user,test.scope", "password," + GRANT_TYPE_REFRESH_TOKEN, true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"), 50000);

        String requestorId = "requestingClient" + new RandomValueStringGenerator().generate();
        setUpClients(requestorId, "uaa.user", "uaa.user", "password," + GRANT_TYPE_USER_TOKEN, true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "uaa.user,test.scope";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String requestorToken = MockMvcUtils.getUserOAuthAccessToken(mockMvc,
                requestorId,
                SECRET,
                username,
                SECRET,
                "uaa.user");

        String response = mockMvc.perform(
                        post("/oauth/token")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + requestorToken)
                                .accept(MediaType.APPLICATION_JSON)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_USER_TOKEN)
                                .param(OAuth2Utils.CLIENT_ID, recipientId)
                                .param(OAuth2Utils.SCOPE, "test.scope")
                                .param("expires_in", "44000")
                )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> result = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {
        });

        String refreshToken = (String) result.get(REFRESH_TOKEN);
        assertThat(refreshToken).isNotNull();
        assertThat(refreshToken.length()).isLessThanOrEqualTo(36);
        assertThat(result).containsEntry("scope", "test.scope");
        assertThat(result.get(ACCESS_TOKEN)).isNull();

        RevocableToken token = revocableTokenProvisioning.retrieve(refreshToken, identityZoneManager.getCurrentIdentityZoneId());
        assertThat(token.getClientId()).isEqualTo(recipientId);

        response = mockMvc.perform(
                        post("/oauth/token")
                                .accept(MediaType.APPLICATION_JSON)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                                .param(REFRESH_TOKEN, refreshToken)
                                .param(OAuth2Utils.CLIENT_ID, recipientId)
                                .param(CLIENT_SECRET, SECRET)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {
        });
    }

    @Test
    void client_credentials_token() throws Exception {
        String recipientId = "recipientClient" + new RandomValueStringGenerator().generate();
        setUpClients(recipientId, "uaa.user", "uaa.user,test.scope", "password," + GRANT_TYPE_REFRESH_TOKEN, true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"), 50000);

        String requestorId = "requestingClient" + new RandomValueStringGenerator().generate();
        setUpClients(requestorId, "uaa.user", "uaa.user", "client_credentials," + GRANT_TYPE_USER_TOKEN, true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "uaa.user,test.scope";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String requestorToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
                mockMvc,
                requestorId,
                SECRET,
                "uaa.user",
                null,
                true);

        mockMvc.perform(
                        post("/oauth/token")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + requestorToken)
                                .accept(MediaType.APPLICATION_JSON)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_USER_TOKEN)
                                .param(OAuth2Utils.CLIENT_ID, recipientId)
                                .param(OAuth2Utils.SCOPE, "test.scope")
                                .param("expires_in", "44000")
                )
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"Authentication containing a user is required\"")));
    }

    @Test
    void invalid_grant_type() throws Exception {
        String recipientId = "recipientClient" + new RandomValueStringGenerator().generate();
        setUpClients(recipientId, "uaa.user", "uaa.user,test.scope", "password," + GRANT_TYPE_REFRESH_TOKEN, true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"), 50000);

        String requestorId = "requestingClient" + new RandomValueStringGenerator().generate();
        setUpClients(requestorId, "uaa.user", "uaa.user", "password", true, TEST_REDIRECT_URI,
                Collections.singletonList("uaa"));

        String username = "testuser" + new RandomValueStringGenerator().generate();
        String userScopes = "uaa.user,test.scope";
        setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, userScopes, OriginKeys.UAA, IdentityZone.getUaaZoneId());

        String requestorToken = MockMvcUtils.getUserOAuthAccessToken(mockMvc,
                requestorId,
                SECRET,
                username,
                SECRET,
                "uaa.user");

        mockMvc.perform(
                        post("/oauth/token")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + requestorToken)
                                .accept(MediaType.APPLICATION_JSON)
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_USER_TOKEN)
                                .param(OAuth2Utils.CLIENT_ID, recipientId)
                                .param(OAuth2Utils.SCOPE, "test.scope")
                                .param("expires_in", "44000")
                )
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"Unauthorized grant type\"")));
    }

    @Test
    void create_client_with_user_token_grant() throws Exception {
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                "uaa.admin",
                null,
                true
        );

        UaaClientDetails client = new UaaClientDetails(
                generator.generate(),
                null,
                "openid,uaa.user,tokens.",
                TokenConstants.GRANT_TYPE_USER_TOKEN,
                null,
                "http://redirect.uri"
        );
        client.setClientSecret(SECRET);
        mockMvc.perform(
                        post("/oauth/clients")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                                .accept(MediaType.APPLICATION_JSON)
                                .contentType(MediaType.APPLICATION_JSON_VALUE)
                                .content(JsonUtils.writeValueAsString(client))
                )
                .andExpect(status().isCreated());

    }

}
