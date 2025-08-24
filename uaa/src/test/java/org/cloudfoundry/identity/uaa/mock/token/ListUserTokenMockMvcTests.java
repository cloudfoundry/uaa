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
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.List;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ListUserTokenMockMvcTests extends AbstractTokenMockMvcTests {

    private ClientDetails client1withTokensListScope;
    private ClientDetails client2;
    private ClientDetails client3;
    private ScimUser user1withTokensListScope;
    private ScimUser user2;
    private final RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private final MultiValueMap<String, String> tokensPerUser = new LinkedMultiValueMap<>();
    private final MultiValueMap<String, String> tokensPerClient = new LinkedMultiValueMap<>();
    private String adminClientToken;
    private String tokensListToken;

    @BeforeEach
    void createUsersAndClients() throws Exception {
        user1withTokensListScope = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator.generate(), "tokens.list,scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaaZoneId());
        user2 = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator.generate(), "scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaaZoneId());
        ScimUser user3 = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator.generate(), "scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaaZoneId());
        client1withTokensListScope = setUpClients(generator.generate(), "", "tokens.list,scim.read", "password,refresh_token", false);
        client2 = setUpClients(generator.generate(), "", "scim.read", "password,refresh_token", false);
        client3 = setUpClients(generator.generate(), "", "scim.read", "password,refresh_token", false);
        setUpClients(user1withTokensListScope.getId(), "tokens.list", "tokens.list,scim.read", "client_credentials,password,refresh_token", false);

        for (ScimUser user : Arrays.asList(user1withTokensListScope, user2, user3)) {
            for (ClientDetails client : Arrays.asList(client1withTokensListScope, client2, client3)) {
                String token = MockMvcUtils.getUserOAuthAccessToken(
                        mockMvc,
                        client.getClientId(),
                        SECRET,
                        user.getUserName(),
                        SECRET,
                        null,
                        null,
                        true);
                tokensPerUser.add(user.getId(), token);
                tokensPerClient.add(client.getClientId(), token);
            }
        }
        adminClientToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                null,
                null,
                true);

        ClientDetails tokenListClient = setUpClients(generator.generate(),
                "tokens.list",
                null,
                "client_credentials",
                false);
        tokensListToken = getClientCredentialsOAuthAccessToken(
                mockMvc,
                tokenListClient.getClientId(),
                SECRET,
                null,
                null,
                true);
    }

    @Test
    void listUserTokenAsAdmin() throws Exception {
        listTokens("/oauth/token/list/user/" + user1withTokensListScope.getId(), adminClientToken, tokensPerUser.get(user1withTokensListScope.getId()), status().isOk());
    }

    @Test
    void listUserTokenAsSelf() throws Exception {
        String user2Token = tokensPerUser.getFirst(user2.getId());
        listTokens("/oauth/token/list", user2Token, emptyList(), status().isForbidden());
    }

    void validateTokens(List<String> actual, List<String> expected) {
        for (String t : expected) {
            assertThat(actual).as("Expecting token:" + t + " to be present in list.").contains(t);
        }
    }

    List<String> getTokenIds(List<RevocableToken> tokens) {
        return tokens.stream().map(RevocableToken::getTokenId).toList();
    }

    @Test
    void listClientToken_with_TokensList_Scope() throws Exception {
        for (String clientId : Arrays.asList(client1withTokensListScope.getClientId(), client2.getClientId(), client3.getClientId())) {
            listTokens("/oauth/token/list/client/" + clientId, tokensListToken, tokensPerClient.get(clientId), status().isOk());
        }
    }

    @Test
    void listClientTokenAsAdmin() throws Exception {
        for (String clientId : Arrays.asList(client1withTokensListScope.getClientId(), client2.getClientId(), client3.getClientId())) {
            listTokens("/oauth/token/list/client/" + clientId, adminClientToken, tokensPerClient.get(clientId), status().isOk());
        }
    }

    @Test
    void listClientTokenAs_Other_Client() throws Exception {
        for (String clientId : Arrays.asList(client1withTokensListScope.getClientId(), client2.getClientId(), client3.getClientId())) {
            listTokens("/oauth/token/list/client/" + clientId, adminClientToken, tokensPerClient.get(clientId), status().isOk());
        }
    }

    @Test
    void listUserTokenAsAnotherUser() throws Exception {
        getTokenList("/oauth/token/list/user/" + user1withTokensListScope.getId(),
                tokensPerUser.getFirst(user2.getId()),
                status().isForbidden());
    }

    @Test
    void listClientTokensAsAnotherClient() throws Exception {
        getTokenList("/oauth/token/list/client/" + client1withTokensListScope.getClientId(),
                tokensPerClient.getFirst(client3.getClientId()),
                status().isForbidden());

        getTokenList("/oauth/token/list/client/" + client1withTokensListScope.getClientId(),
                tokensListToken,
                status().isOk());
    }

    @Test
    void listUserTokens_for_self() throws Exception {
        String userId = user2.getId();
        listTokens("/oauth/token/list/user/" + userId, tokensPerUser.getFirst(userId), emptyList(), status().isForbidden());
    }

    @Test
    void listUserTokens_for_someone_else() throws Exception {

        getTokenList("/oauth/token/list/user/" + user2.getId(),
                tokensPerUser.getFirst(user1withTokensListScope.getId()),
                status().isOk());

        getTokenList("/oauth/token/list/user/" + user1withTokensListScope.getId(),
                tokensPerUser.getFirst(user2.getId()),
                status().isForbidden());
    }

    @Test
    void listUserTokens_using_TokensList_scope() throws Exception {
        String userId = user1withTokensListScope.getId();
        listTokens("/oauth/token/list/user/" + userId, tokensPerUser.getFirst(userId), tokensPerUser.get(userId), status().isOk());
    }

    void listTokens(String urlTemplate, String accessToken, List<String> expectedTokenIds, ResultMatcher status) throws Exception {
        List<RevocableToken> tokens = getTokenList(urlTemplate,
                accessToken,
                status);

        List<String> tokenIds = getTokenIds(tokens);
        validateTokens(tokenIds, expectedTokenIds);
    }

    @Test
    void listClientTokens() throws Exception {
        listTokens("/oauth/token/list/client/" + client1withTokensListScope.getClientId(), tokensPerClient.getFirst(client1withTokensListScope.getClientId()), tokensPerClient.get(client1withTokensListScope.getClientId()), status().isOk());
    }

    List<RevocableToken> getTokenList(String urlTemplate,
                                      String accessToken,
                                      ResultMatcher status) throws Exception {
        MvcResult result = mockMvc
                .perform(
                        get(urlTemplate)
                                .header(AUTHORIZATION, "Bearer " + accessToken)
                )
                .andExpect(status)
                .andReturn();
        if (result.getResponse().getStatus() == 200) {
            String response = result.getResponse().getContentAsString();
            List<RevocableToken> tokenList = JsonUtils.readValue(response, new TypeReference<List<RevocableToken>>() {
            });
            tokenList.forEach(t -> assertThat(t.getValue()).isNull());
            return tokenList;
        } else {
            return emptyList();
        }
    }
}
