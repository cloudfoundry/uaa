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

import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ListUserTokenMockMvcTests extends AbstractTokenMockMvcTests {

    private ClientDetails client1, client2,client3;
    private ScimUser user1, user2, user3;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    MultiValueMap<String, String> tokensPerUser = new LinkedMultiValueMap<>();
    MultiValueMap<String, String> tokensPerClient = new LinkedMultiValueMap<>();
    private String adminClientToken;
    private String clientWithUser1IdAsIdToken;



    @Before
    public void createUsersAndClients() throws Exception {
        user1 = setUpUser(generator.generate(), "uaa.user,scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaa().getId());
        user2 = setUpUser(generator.generate(), "uaa.user,scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaa().getId());
        user3 = setUpUser(generator.generate(), "uaa.user,scim.read,scim.write", OriginKeys.UAA, IdentityZone.getUaa().getId());
        client1 = setUpClients(generator.generate(), "", "uaa.user,scim.read","password,refresh_token", false);
        client2 = setUpClients(generator.generate(), "", "uaa.user,scim.read","password,refresh_token", false);
        client3 = setUpClients(generator.generate(), "", "uaa.user,scim.read","password,refresh_token", false);
        setUpClients(user1.getId(), "uaa.user", "uaa.user,scim.read","client_credentials,password,refresh_token", false);

        for (ScimUser user : Arrays.asList(user1, user2, user3)) {
            for (ClientDetails client : Arrays.asList(client1, client2, client3)) {
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
        adminClientToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
            getMockMvc(),
            "admin",
            "adminsecret",
            null,
            null,
            true);

        clientWithUser1IdAsIdToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
            getMockMvc(),
            user1.getId(),
            SECRET,
            null,
            null,
            true);

    }

    @Test
    public void listUserTokenAsAdmin() throws Exception {
        List<RevocableToken> tokens = getTokenList("/oauth/token/list/user/" + user1.getId(),
                                                   adminClientToken,
                                                   status().isOk());
        List<String> tokenIds = getTokenIds(tokens);
        validateTokens(tokenIds, tokensPerUser.get(user1.getId()));
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
    public void listClientTokenAsAdmin() throws Exception {
        List<RevocableToken> tokens = getTokenList("/oauth/token/list/client/" + client1.getClientId(),
                                                   adminClientToken,
                                                   status().isOk());
        List<String> tokenIds = getTokenIds(tokens);
        validateTokens(tokenIds, tokensPerClient.get(client1.getClientId()));
    }

    @Test
    public void listUserTokenAsAnotherUser() throws Exception {
        getTokenList("/oauth/token/list/user/" + user1.getId(),
                     tokensPerUser.getFirst(user2.getId()),
                     status().isForbidden());
    }

    @Test
    public void listClientTokensAsAnotherClient() throws Exception {
        getTokenList("/oauth/token/list/client/" + client1.getClientId(),
                     tokensPerClient.getFirst(client3.getClientId()),
                     status().isForbidden());
    }

    @Test
    public void listUserTokensAsAClient() throws Exception {
        getTokenList("/oauth/token/list/user/" + user1.getId(),
                     clientWithUser1IdAsIdToken,
                     status().isForbidden());
    }

    @Test
    public void listUserTokens() throws Exception {
        List<RevocableToken> tokens = getTokenList("/oauth/token/list/user/" + user1.getId(),
                                                   tokensPerUser.getFirst(user1.getId()),
                                                   status().isOk());
        List<String> tokenIds = getTokenIds(tokens);
        validateTokens(tokenIds, tokensPerUser.get(user1.getId()));
    }

    @Test
    public void listClientTokens() throws Exception {
        List<RevocableToken> tokens = getTokenList("/oauth/token/list/client/" + client1.getClientId(),
                                                   tokensPerClient.getFirst(client1.getClientId()),
                                                   status().isOk());
        List<String> tokenIds = getTokenIds(tokens);
        validateTokens(tokenIds, tokensPerClient.get(client1.getClientId()));
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
            .andReturn();
        if (result.getResponse().getStatus() == 200) {
            String response = result.getResponse().getContentAsString();
            return JsonUtils.readValue(response, new TypeReference<List<RevocableToken>>() {});
        } else {
            return Collections.emptyList();
        }
    }



}
