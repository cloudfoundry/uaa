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
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ListUserTokenMockMvcTests extends AbstractTokenMockMvcTests {

    private ClientDetails client1withTokensListScope, client2,client3;
    private ScimUser user1withTokensListScope, user2, user3;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    MultiValueMap<String, String> tokensPerUser = new LinkedMultiValueMap<>();
    MultiValueMap<String, String> tokensPerClient = new LinkedMultiValueMap<>();
    private String adminClientToken;
    private String tokensListToken;
    private String clientWithUser1IdAsIdToken;



    @Before
    public void createUsersAndClients() throws Exception {
        user1withTokensListScope = setUpUser(generator.generate(), "tokens.list,scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaa().getId());
        user2 = setUpUser(generator.generate(), "scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaa().getId());
        user3 = setUpUser(generator.generate(), "scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaa().getId());
        client1withTokensListScope = setUpClients(generator.generate(), "", "tokens.list,scim.read", "password,refresh_token", false);
        client2 = setUpClients(generator.generate(), "", "scim.read","password,refresh_token", false);
        client3 = setUpClients(generator.generate(), "", "scim.read","password,refresh_token", false);
        setUpClients(user1withTokensListScope.getId(), "tokens.list", "tokens.list,scim.read", "client_credentials,password,refresh_token", false);

        for (ScimUser user : Arrays.asList(user1withTokensListScope, user2, user3)) {
            for (ClientDetails client : Arrays.asList(client1withTokensListScope, client2, client3)) {
                String token = MockMvcUtils.getUserOAuthAccessToken(
                    getMockMvc(),
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
            getMockMvc(),
            "admin",
            "adminsecret",
            null,
            null,
            true);

        clientWithUser1IdAsIdToken = getClientCredentialsOAuthAccessToken(
            getMockMvc(),
            user1withTokensListScope.getId(),
            SECRET,
            null,
            null,
            true);

        ClientDetails tokenListClient = setUpClients(generator.generate(),
                                                     "tokens.list",
                                                     null,
                                                     "client_credentials",
                                                     false);
        tokensListToken = getClientCredentialsOAuthAccessToken(
            getMockMvc(),
            tokenListClient.getClientId(),
            SECRET,
            null,
            null,
            true);

    }

    @Test
    public void listUserTokenAsAdmin() throws Exception {
        listTokens("/oauth/token/list/user/" + user1withTokensListScope.getId(), adminClientToken, tokensPerUser.get(user1withTokensListScope.getId()));
    }

    @Test
    public void listUserTokenAsSelf() throws Exception {
        String user2Token = tokensPerUser.getFirst(user2.getId());
        listTokens("/oauth/token/list", user2Token, Arrays.asList(user2Token));
    }

    protected void validateTokens(List<String> actual, List<String> expected) {
        for (String t : expected) {
            assertTrue("Expecting token:"+t+" to be present in list.", actual.contains(t));
        }
    }

    protected List<String> getTokenIds(List<RevocableToken> tokens) {
        List<String> accessTokens = tokens.stream().map(RevocableToken::getTokenId).collect(Collectors.toList());
        return accessTokens;

    }

    @Test
    public void listClientToken_with_TokensList_Scope() throws Exception {
        for (String clientId : Arrays.asList(client1withTokensListScope.getClientId(), client2.getClientId(), client3.getClientId())) {
            listTokens("/oauth/token/list/client/" + clientId, tokensListToken, tokensPerClient.get(clientId));
        }
    }

    @Test
    public void listClientTokenAsAdmin() throws Exception {
        for (String clientId : Arrays.asList(client1withTokensListScope.getClientId(), client2.getClientId(), client3.getClientId())) {
            listTokens("/oauth/token/list/client/" + clientId, adminClientToken, tokensPerClient.get(clientId));
        }
    }

    @Test
    public void listClientTokenAs_Other_Client() throws Exception {
        for (String clientId : Arrays.asList(client1withTokensListScope.getClientId(), client2.getClientId(), client3.getClientId())) {
            listTokens("/oauth/token/list/client/" + clientId, adminClientToken, tokensPerClient.get(clientId));
        }
    }

    @Test
    public void listUserTokenAsAnotherUser() throws Exception {
        getTokenList("/oauth/token/list/user/" + user1withTokensListScope.getId(),
                     tokensPerUser.getFirst(user2.getId()),
                     status().isForbidden());
    }

    @Test
    public void listClientTokensAsAnotherClient() throws Exception {
        getTokenList("/oauth/token/list/client/" + client1withTokensListScope.getClientId(),
                     tokensPerClient.getFirst(client3.getClientId()),
                     status().isForbidden());

        getTokenList("/oauth/token/list/client/" + client1withTokensListScope.getClientId(),
                     tokensListToken,
                     status().isOk());
    }

    @Test
    public void listUserTokens_for_self() throws Exception {
        String userId = user2.getId();
        listTokens("/oauth/token/list/user/" + userId, tokensPerUser.getFirst(userId), Arrays.asList(tokensPerUser.getFirst(userId)));
    }

    @Test
    public void listUserTokens_for_someone_else() throws Exception {

        getTokenList("/oauth/token/list/user/" + user2.getId(),
                     tokensPerUser.getFirst(user1withTokensListScope.getId()),
                     status().isOk());

        getTokenList("/oauth/token/list/user/" + user1withTokensListScope.getId(),
                     tokensPerUser.getFirst(user2.getId()),
                     status().isForbidden());
    }

    @Test
    public void listUserTokens_using_TokensList_scope() throws Exception {
        String userId = user1withTokensListScope.getId();
        listTokens("/oauth/token/list/user/" + userId, tokensPerUser.getFirst(userId), tokensPerUser.get(userId));
    }

    protected void listTokens(String urlTemplate, String accessToken, List<String> expectedTokenIds) throws Exception {
        List<RevocableToken> tokens = getTokenList(urlTemplate,
                                                   accessToken,
                                                   status().isOk());
        List<String> tokenIds = getTokenIds(tokens);
        validateTokens(tokenIds, expectedTokenIds);
    }

    @Test
    public void listClientTokens() throws Exception {
        listTokens("/oauth/token/list/client/" + client1withTokensListScope.getClientId(), tokensPerClient.getFirst(client1withTokensListScope.getClientId()), tokensPerClient.get(client1withTokensListScope.getClientId()));
    }

    protected List<RevocableToken> getTokenList(String urlTemplate,
                                                String accessToken,
                                                ResultMatcher status) throws Exception {
        MvcResult result = getMockMvc()
            .perform(
                get(urlTemplate)
                   .header(AUTHORIZATION, "Bearer "+ accessToken)
            )
            .andExpect(status)
            .andDo(print())
            .andReturn();
        if (result.getResponse().getStatus() == 200) {
            String response = result.getResponse().getContentAsString();
            return JsonUtils.readValue(response, new TypeReference<List<RevocableToken>>() {});
        } else {
            return Collections.emptyList();
        }
    }



}
